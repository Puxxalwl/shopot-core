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
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace shopot::signal {

constexpr int kMaxAgeSeconds = 120;  // a connection code older than this is stale

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
// room or staleness (> kMaxAgeSeconds)
inline std::string open_code(const crypto::Arr<32>& key, const std::string& sealed) {
  if (sealed.size() < 8 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
    throw std::runtime_error("signaling payload too short");
  std::int64_t ts = 0;
  for (int b = 0; b < 8; ++b)
    ts = (ts << 8) | static_cast<std::uint8_t>(sealed[static_cast<std::size_t>(b)]);
  const std::int64_t now = now_unix_s();
  if (ts > now + kMaxAgeSeconds || ts < now - kMaxAgeSeconds)
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
