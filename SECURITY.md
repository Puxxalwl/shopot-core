# Security policy

## Scope

shopot-core protects message content, files and local history against
everyone except the two endpoints. See the threat model in
[README.md](README.md#threat-model--honest-version) and
[docs/PROTOCOL.md](docs/PROTOCOL.md#9-what-an-observer-can-learn) for exactly
what is and is not covered.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

- Open a private report via GitHub's *Security → Report a vulnerability* tab
  on the repository, or
- contact the maintainer through the channels listed on their GitHub profile.

Include: affected commit, a description, a proof of concept if possible, and
whether the issue breaks confidentiality, integrity, authentication, or
availability. We aim to acknowledge within 72 hours.

## Cryptographic inventory

| primitive | implementation | used for |
|-----------|----------------|----------|
| X25519    | libsodium      | identity encryption key, ephemeral ECDH, ratchet DH steps |
| Ed25519   | libsodium      | identity signatures (handshake auth) |
| XSalsa20-Poly1305 | libsodium | AEAD for envelopes, chunks, at-rest records |
| Double ratchet | own code on libsodium HMAC | per-message keys, alternating DH rotation (PCS) |
| HKDF-SHA256 | built on libsodium HMAC | key derivation |
| SHA-256   | libsodium      | fingerprints, room hash, file integrity |
| BIP-39    | own code (tests cover checksum) | mnemonic ↔ entropy |

Design rules: no custom primitives, random 24-byte nonces (safe for
XSalsa20), message keys used exactly once and wiped, ratchet rotations
strictly alternating (race-free by construction), identity/ratchet/storage
secrets wiped when their owning objects die, authentication failures drop
frames silently without oracle behaviour.

## Hardening notes for app developers

- Store the mnemonic in the OS keychain/keystore, never in plaintext files.
- Prompt users to compare fingerprints when adding contacts.
- Consider passphrase-on-top for the DB on shared devices (the storage key is
  derived from the mnemonic; whoever has the words has the history).
- Use `Engine::wipe()` for panic/delete flows — it destroys history,
  outbox, files and contacts. The identity survives (it is the mnemonic).
