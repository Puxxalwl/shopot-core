# Security policy

**English** | [Русский](SECURITY.ru.md)

## Scope

shopot-core protects message content, files, and local history against
everyone except the two endpoints. The exact boundary of what is and is not
covered: the threat model in
[zig/docs/PROTOCOL.md](zig/docs/PROTOCOL.md#18-what-an-observer-can-learn).

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

- Open a private report via GitHub's *Security → Report a vulnerability* tab
  on the repository, or
- contact the maintainer through the channels listed on their GitHub
  profile.

Include: the affected commit, a description, a proof of concept if possible,
and whether the issue breaks confidentiality, integrity, authentication, or
availability. We aim to acknowledge within 72 hours.

## Cryptographic inventory

| Primitive | Implementation | Used for |
|---|---|---|
| X25519 | std.crypto | identity encryption key, ephemeral ECDH, ratchet DH steps |
| Ed25519 | std.crypto | identity signatures (handshake auth, JOIN binding) |
| ChaCha20-Poly1305 | std.crypto | AEAD for envelopes, frames, at-rest records, call frames |
| Symmetric ratchet | own code on std HKDF/HMAC | per-message keys (peek/commit per Double Ratchet spec §3.5) |
| DH ratchet (PCS) | own code on std X25519/HKDF | epoch rotation every 256 sent messages: both sides exchange fresh X25519 publics (RATCHET_KEY envelope) and re-derive chains via a joint DH step |
| HKDF-SHA256 | std.crypto.kdf | all key derivation |
| HMAC-SHA256 | std.crypto | ratchet chain stepping, relay markers, JOIN proofs |
| BLAKE2s-256 / SHA-256 | std.crypto | fingerprints, transcript hash, content addressing (files, avatars), integrity |

The handshake additionally verifies the remote static X25519 key from
m2/m3 against the known contact bundle (KeyMismatch closes the connection),
per the noise-libp2p practice of validating the remote static after an XX
handshake.

Design rules enforced in review:

- No custom primitives — only composition of std.crypto.
- Counter-derived nonces: no (key, nonce) reuse by construction.
- Message keys used exactly once and wiped.
- The receive chain advances only after a successful decrypt.
- Identity/ratchet/storage secrets are wiped with `secureZero` when their
  owning objects die.
- Authentication failures drop frames silently, without oracle behavior.

## Hardening notes for client developers

- The seed file is the identity: keep `~/.shopot/zig-seed` (0600) out of any
  backup/sync that is not itself E2EE. Whoever has the seed has the history.
- Prompt users to compare fingerprints when adding contacts (protection
  against MITM on first contact).
- Store the seed on shared devices only with additional protection
  (passphrase-on-top is a client concern; the core derives everything from
  the raw seed).
- Panic/delete flows: destroying `~/.shopot` (seed, log, files) erases
  history, outbox, files, and contacts. The identity (the seed) survives by
  design — delete `zig-seed` too if the identity itself must die.