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
| X25519    | std.crypto     | identity encryption key, ephemeral ECDH, ratchet DH steps |
| Ed25519   | std.crypto     | identity signatures (handshake auth, JOIN binding) |
| ChaCha20-Poly1305 | std.crypto | AEAD for envelopes, frames, at-rest records |
| Symmetric ratchet | own code on std HKDF/HMAC | per-message keys (advance-on-decrypt per Double Ratchet spec §3.5) |
| DH ratchet (PCS) | own code on std X25519/HKDF | epoch rotation every 256 sent messages: both sides exchange fresh X25519 pubs (RATCHET_KEY envelope) and re-derive chains via a joint DH step |
| HKDF-SHA256 | std.crypto.kdf | key derivation |
| BLAKE2s-256 / SHA-256 | std.crypto | fingerprints, transcript hash, file integrity |
| BIP-39    | own code (tests cover checksum) | mnemonic ↔ entropy |

Handshake additionally verifies the remote static X25519 key from m2/m3
against the known contact bundle (KeyMismatch closes the connection), per
the noise-libp2p practice of validating the remote static after an XX
handshake. Design rules: no custom primitives, counter-derived nonces
(no (key, nonce) reuse by construction), message keys used exactly once and
wiped, receive chain advances only after a successful decrypt, identity/
ratchet/storage secrets wiped when their owning objects die, authentication
failures drop frames silently without oracle behaviour.

## Hardening notes for app developers

- Store the mnemonic in the OS keychain/keystore, never in plaintext files.
- Prompt users to compare fingerprints when adding contacts.
- Consider passphrase-on-top for the DB on shared devices (the storage key is
  derived from the mnemonic; whoever has the words has the history).
- Use `Engine::wipe()` for panic/delete flows — it destroys history,
  outbox, files and contacts. The identity survives (it is the mnemonic).
