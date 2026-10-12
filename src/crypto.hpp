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

#include <array>
#include <cstdint>
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

} // namespace shopot::crypto
