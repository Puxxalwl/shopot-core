// shopot-core — cryptographic primitives.
//
// Identity model:
//   16 bytes of entropy  <->  12-word BIP-39 mnemonic (the "account")
//   entropy --HKDF--> X25519 identity key (encryption)
//                  +-> Ed25519 identity key (signatures)
//                  +-> 32-byte storage key (encrypts the local SQLite DB at rest)
//
// Session model (per contact, per connection):
//   hello handshake: ephemeral X25519 key signed by the Ed25519 identity key,
//   bound to a "room hash" of both identity keys. The resulting session key
//   gives forward secrecy: recorded traffic cannot be decrypted later even if
//   the device is compromised.
#pragma once

#include <sodium.h>

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace shopot::crypto {

using Bytes = std::vector<std::uint8_t>;
template <std::size_t N> using Arr = std::array<std::uint8_t, N>;

/// Must be called once before any other function here (idempotent).
void init();

// ---------------------------------------------------------------- mnemonic

/// Generate a fresh 12-word mnemonic (128-bit entropy).
std::string mnemonic_generate();
/// Validate word count, dictionary membership and the BIP-39 checksum.
bool mnemonic_validate(std::string_view phrase);
/// Recover the 16-byte entropy from a valid mnemonic. Throws std::invalid_argument.
Arr<16> mnemonic_to_entropy(std::string_view phrase);

// ---------------------------------------------------------------- identity

struct Identity {
  Arr<32> enc_pk;    // X25519 public
  Arr<32> enc_sk;    // X25519 secret
  Arr<32> sign_pk;   // Ed25519 public
  Arr<64> sign_sk;   // Ed25519 secret
  Arr<32> storage;   // local-DB encryption key

  static Identity from_entropy(const Arr<16>& entropy);

  /// base64url(enc_pk || sign_pk) — this is what users exchange to add contacts.
  std::string bundle_b64() const;
  static bool bundle_parse(std::string_view b64, Arr<32>& enc_pk_out, Arr<32>& sign_pk_out);

  /// Human-verifiable safety number: SHA-256 over both public keys, grouped hex.
  std::string fingerprint() const;
  static std::string fingerprint_of(const Arr<32>& enc_pk, const Arr<32>& sign_pk);
};

/// Symmetric pairwise "room" identifier: SHA-256(tag || min(signA,signB) || max(...)).
/// Both sides compute the same value; outsiders cannot derive it from one key.
Arr<32> room_hash(const Arr<32>& sign_pk_a, const Arr<32>& sign_pk_b);

// ---------------------------------------------------------------- session

struct Hello {
  Arr<32> epub;
  std::int64_t ts;
  Arr<64> sig;
};

/// Build a signed hello frame; outputs the ephemeral secret to keep.
Bytes hello_make(const Identity& id, const Arr<32>& room, Arr<32>& eph_sk_out);
/// Parse and verify a hello frame against the peer's identity key and room.
/// Throws std::runtime_error on any verification failure.
Hello hello_parse(const Bytes& frame, const Arr<32>& room, const Arr<32>& peer_sign_pk);

/// Derive the 32-byte session key from our ephemeral secret and the peer's
/// ephemeral public key, bound to the room hash. Throws on low-order shared secret.
Arr<32> session_key(const Arr<32>& eph_sk, const Arr<32>& peer_epub, const Arr<32>& room);

// ---------------------------------------------------------------- ratchet

/// Signal-style double ratchet adapted to shopot's session model.
///
/// Bootstrap: both send chains are derived directly from the handshake shared
/// secret (no extra round trip, either side may speak first). Afterwards a
/// message key is evolved for EVERY frame (forward secrecy per message) and
/// the DH keys rotate on a strictly alternating schedule: a side may re-key
/// only after it observed the peer's latest ratchet key, so re-keys can never
/// cross in flight. Re-key after rekey_after sends (default 256).
///
/// All secrets are wiped in the destructor.
class DoubleRatchet {
public:
  static constexpr std::uint32_t kRekeyAfter = 256;
  static constexpr std::size_t kMaxSkip = 128;

  enum class Role { Initiator, Responder };  // Initiator = lexicographically smaller sign key

  struct Sealed {
    Arr<32> dh;        // our current ratchet public key (header)
    std::uint32_t pn;  // length of the previous send chain
    std::uint32_t n;   // index in the current send chain
    Bytes body;        // nonce(24) || ciphertext (XSalsa20-Poly1305 under the message key)
  };

  /// role decides which bootstrap chain is "send"; own_eph_* / peer_eph are
  /// the handshake keys (the responder reuses its handshake key as first
  /// inbound DH secret; the initiator reuses it for its first re-key step).
  static DoubleRatchet bootstrap(const Arr<32>& root, Role role, const Arr<32>& own_eph_sk,
                                 const Arr<32>& peer_eph_pub,
                                 std::uint32_t rekey_after = kRekeyAfter);

  Sealed encrypt(const std::uint8_t* data, std::size_t len);
  Sealed encrypt(std::string_view s) {
    return encrypt(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  }
  /// Throws std::runtime_error on authentication failure or desync.
  Bytes decrypt(const Arr<32>& dh, std::uint32_t pn, std::uint32_t n, const std::uint8_t* body,
                std::size_t len);

  DoubleRatchet() = default;
  ~DoubleRatchet();
  DoubleRatchet(DoubleRatchet&&) noexcept;
  DoubleRatchet& operator=(DoubleRatchet&&) noexcept;
  DoubleRatchet(const DoubleRatchet&) = delete;
  DoubleRatchet& operator=(const DoubleRatchet&) = delete;

private:
  Arr<32> root_{};
  Arr<32> dhs_sk_{};   // our current ratchet secret (handshake key until first re-key)
  Arr<32> dhs_pk_{};
  Arr<32> cks_{};      // send chain key
  Arr<32> ckr_{};      // receive chain key
  Arr<32> send_remote_{};  // peer pub our send chain is bound to
  Arr<32> recv_remote_{};  // peer pub our receive chain expects
  bool have_cks_ = false, have_ckr_ = false;
  bool may_rekey_ = false;  // observed a peer pub newer than send_remote_
  std::uint32_t ns_ = 0, nr_ = 0, pn_ = 0;
  std::uint32_t rekey_after_ = kRekeyAfter;
  std::map<std::pair<Arr<32>, std::uint32_t>, Arr<32>> skipped_;  // (dh, n) -> message key

  Arr<32> chain_step(Arr<32>& ck);  // ck' = HMAC(ck, 0x01); returns mk = HMAC(ck, 0x02)
  void dh_ratchet_send();
  void dh_ratchet_recv(const Arr<32>& dh, std::uint32_t pn);
  void skip_to(const Arr<32>& dh, std::uint32_t until);
  void wipe();
};

// ---------------------------------------------------------------- AEAD

/// XSalsa20-Poly1305 seal: returns nonce(24) || ciphertext || tag(16).
Bytes seal(const Arr<32>& key, const std::uint8_t* data, std::size_t len);
inline Bytes seal(const Arr<32>& key, const Bytes& in) { return seal(key, in.data(), in.size()); }
inline Bytes seal(const Arr<32>& key, std::string_view in) {
  return seal(key, reinterpret_cast<const std::uint8_t*>(in.data()), in.size());
}
/// Reverse of seal(). Throws std::runtime_error on authentication failure.
Bytes open(const Arr<32>& key, const std::uint8_t* data, std::size_t len);
inline Bytes open(const Arr<32>& key, const Bytes& in) { return open(key, in.data(), in.size()); }

// ---------------------------------------------------------------- util

std::string b64e(const std::uint8_t* data, std::size_t len);  // base64url, no padding
Bytes b64d(std::string_view s);                                // throws on garbage
std::string hex_lower(const std::uint8_t* data, std::size_t len);
Arr<32> sha256(const std::uint8_t* data, std::size_t len);
Arr<32> random32();
std::string new_id();  // 16 random bytes as 32 lowercase hex chars


// per-call audio keys: HKDF-SHA256(ikm = room_hash || call_id || role)
inline crypto::Arr<32> call_key_for(const crypto::Arr<32>& room, const std::string& call_id,
                                    char role) {
  const std::string salt = "shopot-call-v1";
  crypto::Bytes ikm;
  ikm.reserve(room.size() + call_id.size() + 1);
  ikm.insert(ikm.end(), room.begin(), room.end());
  ikm.insert(ikm.end(), call_id.begin(), call_id.end());
  ikm.push_back(static_cast<std::uint8_t>(role));

  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, reinterpret_cast<const unsigned char*>(salt.data()),
                              static_cast<unsigned long long>(salt.size()));
  crypto_auth_hmacsha256_update(&st, ikm.data(), ikm.size());
  crypto::Arr<32> prk;
  crypto_auth_hmacsha256_final(&st, prk.data());

  const std::string info = "shopot-call-audio-v1";
  crypto_auth_hmacsha256_init(&st, prk.data(), prk.size());
  crypto_auth_hmacsha256_update(&st, reinterpret_cast<const unsigned char*>(info.data()),
                                static_cast<unsigned long long>(info.size()));
  const std::uint8_t one = 1;
  crypto_auth_hmacsha256_update(&st, &one, 1);
  crypto::Arr<32> okm;
  crypto_auth_hmacsha256_final(&st, okm.data());
  return okm;
}

} // namespace shopot::crypto
