#pragma once

// Rendezvous abstraction: peers publish sealed connection codes under a topic
// derived from the pairwise room hash. A relay is an untrusted mailbox — it
// sees an opaque topic hash and an opaque sealed blob, nothing else. The
// sealed payload format and the manual codes are the same base64url JSON, so
// automatic discovery and manual exchange are interchangeable.

#include "../crypto.hpp"

#include <sodium.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace shopot::signal {

constexpr int kMaxAgeSeconds = 120;      // a connection code older than this is stale
constexpr int kInviteMaxAgeSeconds = 30 * 24 * 3600;  // invites may redeem offline, later

// ---------------------------------------------------------------- invites
// An invite is a capability: its holder can find the invite topic and prove
// membership. Format: "shopot://i/" + base64url(enc_pk(32) || sign_pk(32) ||
// secret(16)). The secret (not the public keys) keys and names the topic, so
// knowing someone's public bundle alone reveals nothing about their invites.

struct InviteParts {
  crypto::Arr<32> enc_pk;
  crypto::Arr<32> sign_pk;
  crypto::Arr<16> secret;
};

inline std::string make_invite_code(const crypto::Arr<32>& enc_pk, const crypto::Arr<32>& sign_pk,
                                    const crypto::Arr<16>& secret) {
  std::vector<std::uint8_t> raw;
  raw.reserve(80);
  raw.insert(raw.end(), enc_pk.begin(), enc_pk.end());
  raw.insert(raw.end(), sign_pk.begin(), sign_pk.end());
  raw.insert(raw.end(), secret.begin(), secret.end());
  return "shopot://i/" + crypto::b64e(raw.data(), raw.size());
}

// accepts both the full "shopot://i/..." form and the bare base64url body
inline InviteParts parse_invite_code(const std::string& code) {
  static const std::string kPrefix = "shopot://i/";
  std::string body = code;
  if (body.rfind(kPrefix, 0) == 0) body = body.substr(kPrefix.size());
  const crypto::Bytes raw = crypto::b64d(body);
  if (raw.size() != 80) throw std::runtime_error("bad invite code");
  InviteParts p;
  std::memcpy(p.enc_pk.data(), raw.data(), 32);
  std::memcpy(p.sign_pk.data(), raw.data() + 32, 32);
  std::memcpy(p.secret.data(), raw.data() + 64, 16);
  return p;
}

// topic = hex( SHA-256("shopot-invite-v1" || sign_pk_A || secret)[0..16] )
inline std::string invite_topic_for(const crypto::Arr<32>& inviter_sign_pk,
                                    const crypto::Arr<16>& secret) {
  const std::string salt = "shopot-invite-v1";
  crypto_hash_sha256_state hs;
  crypto_hash_sha256_init(&hs);
  crypto_hash_sha256_update(&hs, reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size());
  crypto_hash_sha256_update(&hs, inviter_sign_pk.data(), inviter_sign_pk.size());
  crypto_hash_sha256_update(&hs, secret.data(), secret.size());
  crypto::Arr<32> d{};
  crypto_hash_sha256_final(&hs, d.data());
  return crypto::hex_lower(d.data(), 16);
}

// key = HKDF-SHA256(ikm=secret, salt="shopot-invite-v1")
inline crypto::Arr<32> invite_key_for(const crypto::Arr<16>& secret) {
  const std::string salt = "shopot-invite-v1";
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, reinterpret_cast<const unsigned char*>(salt.data()),
                              static_cast<unsigned long long>(salt.size()));
  crypto_auth_hmacsha256_update(&st, secret.data(), secret.size());
  crypto::Arr<32> prk;
  crypto_auth_hmacsha256_final(&st, prk.data());

  const std::string info = "shopot-invite-key-v1";
  crypto_auth_hmacsha256_init(&st, prk.data(), prk.size());
  crypto_auth_hmacsha256_update(&st, reinterpret_cast<const unsigned char*>(info.data()),
                                static_cast<unsigned long long>(info.size()));
  const std::uint8_t one = 1;
  crypto_auth_hmacsha256_update(&st, &one, 1);
  crypto::Arr<32> okm;
  crypto_auth_hmacsha256_final(&st, okm.data());
  return okm;
}

// signal key = HKDF-SHA256(ikm=room_hash, salt="shopot-signal-v1")
// (built directly on libsodium HMAC — the same extract/expand structure as
// every other key in shopot; no new primitives)
inline crypto::Arr<32> key_for(const crypto::Arr<32>& room) {
  const std::string salt = "shopot-signal-v1";
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, reinterpret_cast<const unsigned char*>(salt.data()),
                              static_cast<unsigned long long>(salt.size()));
  crypto_auth_hmacsha256_update(&st, room.data(), room.size());
  crypto::Arr<32> prk;
  crypto_auth_hmacsha256_final(&st, prk.data());

  const std::string info = "shopot-signal-key-v1";
  crypto_auth_hmacsha256_init(&st, prk.data(), prk.size());
  crypto_auth_hmacsha256_update(&st, reinterpret_cast<const unsigned char*>(info.data()),
                                static_cast<unsigned long long>(info.size()));
  const std::uint8_t one = 1;
  crypto_auth_hmacsha256_update(&st, &one, 1);
  crypto::Arr<32> okm;
  crypto_auth_hmacsha256_final(&st, okm.data());
  return okm;
}

// topic = hex( SHA-256("shopot-signal-v1" || room_hash)[0..16] ) — 32 chars;
// identical on both sides, unlinks the rendezvous from any user identity
inline std::string topic_for(const crypto::Arr<32>& room) {
  const std::string salt = "shopot-signal-v1";
  crypto_hash_sha256_state hs;
  crypto_hash_sha256_init(&hs);
  crypto_hash_sha256_update(&hs, reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size());
  crypto_hash_sha256_update(&hs, room.data(), room.size());
  crypto::Arr<32> d{};
  crypto_hash_sha256_final(&hs, d.data());
  return crypto::hex_lower(d.data(), 16);
}

// sealed signaling payload: ts(8, BE unix seconds) || seal(code)
inline std::string seal_code_ts(const crypto::Arr<32>& key, const std::string& code,
                                std::int64_t ts_unix_s) {
  const crypto::Bytes sealed = crypto::seal(key, code);
  std::string out;
  out.reserve(8 + sealed.size());
  for (int b = 7; b >= 0; --b)
    out.push_back(static_cast<char>((static_cast<std::uint64_t>(ts_unix_s) >> (b * 8)) & 0xFF));
  out.append(reinterpret_cast<const char*>(sealed.data()), sealed.size());
  return out;
}

inline std::int64_t now_unix_s() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

inline std::string seal_code(const crypto::Arr<32>& key, const std::string& code) {
  return seal_code_ts(key, code, now_unix_s());
}

// returns the original base64url connection code; throws on tamper, foreign
// room or staleness (> max_age_s)
inline std::string open_code(const crypto::Arr<32>& key, const std::string& sealed,
                             std::int64_t max_age_s = kMaxAgeSeconds) {
  if (sealed.size() < 8 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
    throw std::runtime_error("signaling payload too short");
  std::int64_t ts = 0;
  for (int b = 0; b < 8; ++b)
    ts = (ts << 8) | static_cast<std::uint8_t>(sealed[static_cast<std::size_t>(b)]);
  const std::int64_t now = now_unix_s();
  if (ts > now + max_age_s || ts < now - max_age_s)
    throw std::runtime_error("stale signaling payload");
  const crypto::Bytes plain =
      crypto::open(key, reinterpret_cast<const std::uint8_t*>(sealed.data()) + 8,
                   sealed.size() - 8);
  return std::string(plain.begin(), plain.end());
}

// One rendezvous backend. Implementations deliver asynchronously: subscribe +
// publish are fire-and-forget, poll drains what arrived.
class ISignaling {
public:
  using Msg = std::pair<std::string, std::string>;  // (topic, sealed payload)
  virtual ~ISignaling() = default;
  virtual bool ok() const = 0;  // relay currently reachable
  virtual void subscribe(const std::string& topic) = 0;
  virtual void publish(const std::string& topic, const std::string& payload) = 0;
  // block until everything published so far has left the queue (bounded);
  // call before abandoning the object or the payload may never leave
  virtual bool flush_pending(std::int64_t timeout_ms) = 0;
  virtual std::vector<Msg> poll(std::int64_t wait_ms) = 0;
};

} // namespace shopot::signal
