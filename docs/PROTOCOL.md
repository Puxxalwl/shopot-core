# shopot wire protocol v1

This document specifies everything two independent implementations need to
interoperate. Normative keywords (MUST/SHOULD/MAY) follow RFC 2119.

## 1. Identity

```
entropy      = 16 random bytes
mnemonic     = BIP-39 (English wordlist, 12 words, 4-bit checksum)
master salt  = "shopot-identity-v1"
enc_sk       = HKDF-SHA256(entropy, salt, "enc")      → X25519 keypair
sign_seed    = HKDF-SHA256(entropy, salt, "sign")     → Ed25519 keypair
storage_key  = HKDF-SHA256(entropy, salt, "storage")  → 32-byte symmetric key
```

HKDF uses the salt as the HMAC key (extract) and a single 32-byte expand block.

**Contact bundle** (what users exchange to add each other):
`base64url-nopad(enc_pk || sign_pk)` — 64 bytes → 86 characters.

**Fingerprint** (safety number, for out-of-band MITM verification):
SHA-256(enc_pk || sign_pk), lowercase hex, displayed as 16 groups of 4.

**Room hash** — pairwise, symmetric, binds the handshake to the pair:
`SHA-256("shopot-room-v1" || min(signA, signB) || max(signA, signB))`
(comparison is bytewise on the 32-byte public keys).

## 2. Transport

Ordered, reliable, message-oriented channel. Reference: WebRTC DataChannel
labeled `shopot` over DTLS, ICE with STUN only (no TURN). Any transport with
the same properties satisfies this spec (see `src/transport/channel.hpp`).

### Signaling (manual)

Connection codes are base64url-nopad of UTF-8 JSON:

```json
{
  "type": "offer" | "answer",
  "sdp": "<session description>",
  "candidates": [{"c": "<candidate line>", "m": "<mid>"}, ...]
}
```

Codes are generated only after ICE gathering completes (bounded to 8 s, host
candidates alone are acceptable). Codes are single-use. There is intentionally
no rendezvous server; the application transports codes.

## 3. Framing

Every message on the channel starts with a one-byte type:

| byte  | kind      | body                                                       |
|-------|-----------|------------------------------------------------------------|
| 0x10  | control   | plaintext JSON (handshake only)                            |
| 0x11  | envelope  | nonce(24) ‖ XSalsa20-Poly1305(JSON)                        |
| 0x12  | chunk     | file_id(16) ‖ idx(u32 BE) ‖ nonce(24) ‖ XSalsa20-Poly1305(data ≤ 16384) |

Frames with unknown type bytes, envelopes that fail authentication, and JSON
that fails to parse MUST be dropped silently.

## 4. Handshake

When the channel opens, both sides immediately send a control frame:

```json
{"t":"hello","v":1,"epub":"<b64url X25519 ephemeral>","ts":1700000000,"sig":"<b64url Ed25519>"}
```

- `epub` — fresh random X25519 key, generated per connection attempt.
- `ts` — unix seconds; receivers MUST reject if |now − ts| > 600.
- `sig` — Ed25519 signature by the sender's **identity** key over:
  `"shopot-hello-v1" ‖ room_hash(32) ‖ epub(32) ‖ ts(u64 BE)`

On receiving a valid hello, a side that has not sent its own MUST send it.
When both hellos are verified:

```
shared      = X25519(eph_sk, peer_epub)   // low-order result MUST abort
session_key = HKDF-SHA256(shared, "shopot-session-v1", room_hash)
eph_sk      = securely erased
```

The session key authenticates the peer (only the holder of the identity key
could produce a valid signature) and provides **forward secrecy**: erasing
eph_sk makes the session unrecoverable afterwards.

A side MUST NOT accept envelope/chunk frames before the handshake completes.

## 5. Envelopes

Sealed JSON objects. Common field: `"t"`.

### text
`{"t":"text","id":"<32 hex>","ts":<unix ms>,"body":"<utf-8>"}`

### ack — delivery confirmation
`{"t":"ack","ref":"<id of a text/file envelope>"}`

On `ack`: the sender deletes the outbox entry and marks the message
delivered. On receiving any message envelope, a peer MUST send its ack even
for duplicates (the sender may be re-flushing after a lost connection) but
MUST NOT store or display a duplicate (dedupe by `id`).

### file — transfer metadata
```json
{"t":"file","id":"<32 hex>","ts":<ms>,"file":"<32 hex file id>",
 "name":"report.pdf","mime":"application/pdf","size":1234567,
 "total":76,"hash":"<b64url SHA-256 of plaintext>","voice":false}
```
`voice:true` marks a voice note (apps render it inline). `total` is the
chunk count; `size` in bytes; chunk `i` covers `[i·16384, min((i+1)·16384, size))`.

### fdone — receiver confirms integrity
`{"t":"fdone","file":"<file id>"}`
Sent after the receiver assembled all chunks and the SHA-256 matched. The
sender then marks the outgoing file as delivered.

## 6. Offline queue (the "handshake rendezvous")

There is no server to hold messages, so the **sender's device** holds them:

1. Sending while no session exists stores the envelope (sealed with the
   *storage* key) in the local `outbox` table.
2. Whenever a session with that contact establishes, the outbox is flushed in
   `created_at` order, then pending file transfers start.
3. Entries are deleted only on `ack`. Unacknowledged entries are re-sent on
   the next session; receivers dedupe.

Consequence: two users that are never online simultaneously cannot exchange
messages. This is a mathematical property of serverless design, not a bug.

## 7. File transfer

- The sender streams chunks in order. It SHOULD pause when the channel's
  buffered amount exceeds 1 MiB and resume below 256 KiB (backpressure).
- The receiver stores each chunk sealed with its storage key, keyed by
  (file_id, idx). Duplicate chunks are overwritten and not double-counted,
  which makes restarts after disconnects safe (v1 restarts from chunk 0).
- After the last chunk: decrypt all, hash, compare, write to the download
  directory as `<file_id[:8]>-<sanitized name>`, delete chunks, send fdone.
- A hash mismatch marks the transfer failed; chunks are kept for forensics
  until the next attempt or wipe.

## 8. Storage encryption

SQLite (WAL). Sealed at rest with the identity storage key: message bodies,
outbox payloads, file chunks, meta values. Sealed value layout:
`nonce(24) ‖ ciphertext ‖ Poly1305 tag(16)`. Schema/column names and record
counts are not hidden; all content is.

## 9. What an observer can learn

| observer            | sees                                                            |
|---------------------|-----------------------------------------------------------------|
| ISP / network       | two IPs exchanging DTLS/UDP; timing & volume                    |
| STUN server         | that your IP asked for its reflexive address                    |
| code channel        | the SDP codes (IPs, ports, fingerprints — treat as sensitive)   |
| seized locked device| ciphertext only (storage key derives from the mnemonic)          |

Mitigations: compare fingerprints out-of-band against MITM during code
exchange; disable STUN on LAN/Tor; Tor transport is on the roadmap for
IP-level anonymity.
