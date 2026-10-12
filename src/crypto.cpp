#include "crypto.hpp"

#include "third_party/bip39_english.h"

#include <sodium.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

namespace shopot::crypto {

void init() {
  static const bool ok = (sodium_init() >= 0);
  if (!ok) throw std::runtime_error("sodium_init() failed");
}

static std::int64_t now_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// ------------------------------------------------------------------ helpers

std::string b64e(const std::uint8_t* data, std::size_t len) {
  std::string out(sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
  sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  out.resize(std::strlen(out.c_str()));
  return out;
}

Bytes b64d(std::string_view s) {
  Bytes out(s.size());
  std::size_t out_len = 0;
  if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), nullptr, &out_len, nullptr,
                        sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
    throw std::invalid_argument("invalid base64url");
  out.resize(out_len);
  return out;
}

std::string hex_lower(const std::uint8_t* data, std::size_t len) {
  std::string out(len * 2 + 1, '\0');
  sodium_bin2hex(out.data(), out.size(), data, len);
  out.resize(len * 2);
  return out;
}

Arr<32> sha256(const std::uint8_t* data, std::size_t len) {
  Arr<32> out;
  crypto_hash_sha256(out.data(), data, len);
  return out;
}

Arr<32> random32() {
  Arr<32> out;
  randombytes_buf(out.data(), out.size());
  return out;
}

std::string new_id() {
  Arr<16> raw;
  randombytes_buf(raw.data(), raw.size());
  return hex_lower(raw.data(), raw.size());
}

// ------------------------------------------------------------------ HKDF-SHA256

static Arr<32> hkdf32(const std::uint8_t* ikm, std::size_t ikm_len, std::string_view salt,
                      std::string_view info) {
  // extract
  Arr<32> prk;
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size());
  crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
  crypto_auth_hmacsha256_final(&st, prk.data());
  // expand (single 32-byte block is all we need)
  Arr<32> okm;
  crypto_auth_hmacsha256_state st2;
  crypto_auth_hmacsha256_init(&st2, prk.data(), prk.size());
  crypto_auth_hmacsha256_update(&st2, reinterpret_cast<const std::uint8_t*>(info.data()), info.size());
  const std::uint8_t one = 1;
  crypto_auth_hmacsha256_update(&st2, &one, 1);
  crypto_auth_hmacsha256_final(&st2, okm.data());
  sodium_memzero(prk.data(), prk.size());
  return okm;
}

// ------------------------------------------------------------------ mnemonic

static std::array<std::uint16_t, 12> words_from_entropy(const Arr<16>& e) {
  const Arr<32> hash = sha256(e.data(), e.size());
  std::array<std::uint16_t, 12> out{};
  for (int i = 0; i < 12; ++i) {
    const int bitpos = i * 11;
    std::uint16_t val = 0;
    for (int b = 0; b < 11; ++b) {
      const int p = bitpos + b;
      const int byte = p / 8, bit = 7 - (p % 8);
      const std::uint8_t src = (byte < 16) ? e[byte] : hash[0];  // bits 128..131 = top 4 of hash
      val = static_cast<std::uint16_t>((val << 1) | ((src >> bit) & 1));
    }
    out[i] = val;
  }
  return out;
}

static const std::unordered_map<std::string_view, std::uint16_t>& word_index() {
  static const std::unordered_map<std::string_view, std::uint16_t> map = [] {
    std::unordered_map<std::string_view, std::uint16_t> m;
    m.reserve(2048);
    for (std::uint16_t i = 0; i < 2048; ++i) m.emplace(kBip39English[i], i);
    return m;
  }();
  return map;
}

std::string mnemonic_generate() {
  Arr<16> entropy;
  randombytes_buf(entropy.data(), entropy.size());
  const auto idx = words_from_entropy(entropy);
  std::string out;
  for (int i = 0; i < 12; ++i) {
    if (i) out += ' ';
    out += kBip39English[idx[i]];
  }
  sodium_memzero(entropy.data(), entropy.size());
  return out;
}

Arr<16> mnemonic_to_entropy(std::string_view phrase) {
  std::array<std::uint16_t, 12> idx{};
  int n = 0;
  std::size_t pos = 0;
  while (pos < phrase.size()) {
    const std::size_t sp = phrase.find(' ', pos);
    const std::string_view w = phrase.substr(pos, sp == std::string_view::npos ? sp : sp - pos);
    if (n >= 12) throw std::invalid_argument("mnemonic: too many words");
    const auto it = word_index().find(w);
    if (it == word_index().end()) throw std::invalid_argument("mnemonic: unknown word");
    idx[n++] = it->second;
    if (sp == std::string_view::npos) break;
    pos = sp + 1;
  }
  if (n != 12) throw std::invalid_argument("mnemonic: need exactly 12 words");

  Arr<16> entropy{};
  std::uint8_t checksum = 0;
  for (int i = 0; i < 12; ++i) {
    const int bitpos = i * 11;
    for (int b = 0; b < 11; ++b) {
      const int p = bitpos + b;
      const int byte = p / 8, bit = 7 - (p % 8);
      const std::uint8_t v = static_cast<std::uint8_t>((idx[i] >> (10 - b)) & 1);
      if (byte < 16)
        entropy[byte] |= static_cast<std::uint8_t>(v << bit);
      else
        checksum |= static_cast<std::uint8_t>(v << (7 - (p - 128)));  // top 4 bits
    }
  }
  const Arr<32> hash = sha256(entropy.data(), entropy.size());
  if ((hash[0] & 0xF0) != (checksum & 0xF0)) {
    sodium_memzero(entropy.data(), entropy.size());
    throw std::invalid_argument("mnemonic: bad checksum");
  }
  return entropy;
}

bool mnemonic_validate(std::string_view phrase) {
  try {
    Arr<16> e = mnemonic_to_entropy(phrase);
    sodium_memzero(e.data(), e.size());
    return true;
  } catch (...) {
    return false;
  }
}

// ------------------------------------------------------------------ identity

Identity Identity::from_entropy(const Arr<16>& entropy) {
  Identity id;
  id.enc_sk = hkdf32(entropy.data(), entropy.size(), "shopot-identity-v1", "enc");
  crypto_scalarmult_base(id.enc_pk.data(), id.enc_sk.data());

  const Arr<32> sign_seed = hkdf32(entropy.data(), entropy.size(), "shopot-identity-v1", "sign");
  crypto_sign_seed_keypair(id.sign_pk.data(), id.sign_sk.data(), sign_seed.data());

  id.storage = hkdf32(entropy.data(), entropy.size(), "shopot-identity-v1", "storage");
  return id;
}

std::string Identity::bundle_b64() const {
  std::array<std::uint8_t, 64> raw{};
  std::memcpy(raw.data(), enc_pk.data(), 32);
  std::memcpy(raw.data() + 32, sign_pk.data(), 32);
  return b64e(raw.data(), raw.size());
}

bool Identity::bundle_parse(std::string_view b64, Arr<32>& enc_pk_out, Arr<32>& sign_pk_out) {
  try {
    Bytes raw = b64d(b64);
    if (raw.size() != 64) return false;
    std::memcpy(enc_pk_out.data(), raw.data(), 32);
    std::memcpy(sign_pk_out.data(), raw.data() + 32, 32);
    return true;
  } catch (...) {
    return false;
  }
}

std::string Identity::fingerprint_of(const Arr<32>& enc_pk, const Arr<32>& sign_pk) {
  crypto_hash_sha256_state st;
  crypto_hash_sha256_init(&st);
  crypto_hash_sha256_update(&st, enc_pk.data(), enc_pk.size());
  crypto_hash_sha256_update(&st, sign_pk.data(), sign_pk.size());
  Arr<32> h;
  crypto_hash_sha256_final(&st, h.data());
  const std::string hex = hex_lower(h.data(), h.size());
  std::string out;
  for (int i = 0; i < 16; ++i) {
    if (i) out += ' ';
    out += hex.substr(i * 4, 4);
  }
  return out;
}

std::string Identity::fingerprint() const { return fingerprint_of(enc_pk, sign_pk); }

Arr<32> room_hash(const Arr<32>& a, const Arr<32>& b) {
  const Arr<32>& lo = (a < b) ? a : b;
  const Arr<32>& hi = (a < b) ? b : a;
  crypto_hash_sha256_state st;
  crypto_hash_sha256_init(&st);
  const std::string tag = "shopot-room-v1";
  crypto_hash_sha256_update(&st, reinterpret_cast<const std::uint8_t*>(tag.data()), tag.size());
  crypto_hash_sha256_update(&st, lo.data(), lo.size());
  crypto_hash_sha256_update(&st, hi.data(), hi.size());
  Arr<32> out;
  crypto_hash_sha256_final(&st, out.data());
  return out;
}

// ------------------------------------------------------------------ session

Bytes hello_make(const Identity& id, const Arr<32>& room, Arr<32>& eph_sk_out) {
  randombytes_buf(eph_sk_out.data(), eph_sk_out.size());
  Arr<32> epub;
  crypto_scalarmult_base(epub.data(), eph_sk_out.data());
  const std::int64_t ts = now_seconds();

  // signed transcript: tag || room || epub || ts(big-endian)
  std::vector<std::uint8_t> msg;
  const std::string tag = "shopot-hello-v1";
  msg.insert(msg.end(), tag.begin(), tag.end());
  msg.insert(msg.end(), room.begin(), room.end());
  msg.insert(msg.end(), epub.begin(), epub.end());
  for (int i = 7; i >= 0; --i) msg.push_back(static_cast<std::uint8_t>((std::uint64_t)ts >> (i * 8)));

  Arr<64> sig;
  crypto_sign_detached(sig.data(), nullptr, msg.data(), msg.size(), id.sign_sk.data());

  const nlohmann::json j = {{"t", "hello"},
                            {"v", 1},
                            {"epub", b64e(epub.data(), epub.size())},
                            {"ts", ts},
                            {"sig", b64e(sig.data(), sig.size())}};
  const std::string s = j.dump();
  return Bytes(s.begin(), s.end());
}

Hello hello_parse(const Bytes& frame, const Arr<32>& room, const Arr<32>& peer_sign_pk) {
  const nlohmann::json j = nlohmann::json::parse(frame.begin(), frame.end());
  if (j.value("t", "") != "hello" || j.value("v", 0) != 1) throw std::runtime_error("hello: bad frame");
  Hello h;
  const Bytes epub = b64d(j.at("epub").get<std::string>());
  const Bytes sig = b64d(j.at("sig").get<std::string>());
  if (epub.size() != 32 || sig.size() != 64) throw std::runtime_error("hello: bad fields");
  std::memcpy(h.epub.data(), epub.data(), 32);
  std::memcpy(h.sig.data(), sig.data(), 64);
  h.ts = j.at("ts").get<std::int64_t>();
  if (std::llabs(now_seconds() - h.ts) > 600) throw std::runtime_error("hello: timestamp skew");

  std::vector<std::uint8_t> msg;
  const std::string tag = "shopot-hello-v1";
  msg.insert(msg.end(), tag.begin(), tag.end());
  msg.insert(msg.end(), room.begin(), room.end());
  msg.insert(msg.end(), h.epub.begin(), h.epub.end());
  for (int i = 7; i >= 0; --i) msg.push_back(static_cast<std::uint8_t>((std::uint64_t)h.ts >> (i * 8)));

  if (crypto_sign_verify_detached(h.sig.data(), msg.data(), msg.size(), peer_sign_pk.data()) != 0)
    throw std::runtime_error("hello: bad signature");
  return h;
}

Arr<32> session_key(const Arr<32>& eph_sk, const Arr<32>& peer_epub, const Arr<32>& room) {
  Arr<32> shared;
  if (crypto_scalarmult(shared.data(), eph_sk.data(), peer_epub.data()) != 0)
    throw std::runtime_error("session: low-order public key");
  const Arr<32> key = hkdf32(shared.data(), shared.size(), "shopot-session-v1",
                             std::string_view(reinterpret_cast<const char*>(room.data()), room.size()));
  sodium_memzero(shared.data(), shared.size());
  return key;
}

// ------------------------------------------------------------------ AEAD

Bytes seal(const Arr<32>& key, const std::uint8_t* data, std::size_t len) {
  Bytes out(crypto_secretbox_NONCEBYTES + len + crypto_secretbox_MACBYTES);
  randombytes_buf(out.data(), crypto_secretbox_NONCEBYTES);
  crypto_secretbox_easy(out.data() + crypto_secretbox_NONCEBYTES, data, len, out.data(), key.data());
  return out;
}

Bytes open(const Arr<32>& key, const std::uint8_t* data, std::size_t len) {
  if (len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
    throw std::runtime_error("open: short ciphertext");
  Bytes out(len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
  if (crypto_secretbox_open_easy(out.data(), data + crypto_secretbox_NONCEBYTES,
                                 len - crypto_secretbox_NONCEBYTES, data, key.data()) != 0)
    throw std::runtime_error("open: authentication failed");
  return out;
}

} // namespace shopot::crypto
