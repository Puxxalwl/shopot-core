# shopot Wire Protocol v3

Normative byte-level specification of the shopot P2P messenger wire protocol.
Implementation: `shopot-zig` (this repository). Russian version:
[ru/PROTOCOL.md](ru/PROTOCOL.md).

**Rules of the wire**

- No JSON, no text protocol. All integers are **little-endian** unless a field
  explicitly says BE. Fixed field widths only, **no varint**.
- The protocol version is bound into the handshake transcript and the storage
  header. An incompatible change requires a new version byte — never a
  silent redefinition of an existing field.
- Notation: `u8`/`u16`/`u32`/`u64` are unsigned integers of 1/2/4/8 bytes;
  `[N]` is N raw bytes; `str16` is `[len u16][bytes]` (UTF-8, no terminator).

## 1. Identity

| Object | Construction |
|---|---|
| seed | 32 random bytes, stored only on the owner's device (`~/.shopot/zig-seed`, mode 0600) |
| enc keypair | X25519, scalar = HKDF-SHA256(seed, "shopot-id-v3")[0..32] |
| sign keypair | Ed25519, scalar = HKDF-SHA256(seed, "shopot-id-v3")[32..64] |
| bundle | `enc_pk[32] || sign_pk[32]` — 64 bytes, the only identity material ever transmitted |
| fingerprint | BLAKE2s-256(bundle), rendered hex in groups of 4 — compared by voice between humans to detect MITM |

Both keypairs are deterministically derived, so the seed alone reconstructs
the identity. Whoever holds the seed holds the identity; there is no
revocation mechanism.

## 2. Transport framing (TCP)

Every TCP payload between two peers is a stream of frames:

```
[len u16 LE][payload]
```

Two modes on the same stream:

1. **handshake** — the 3-message XX-like exchange (§3), sent as plain frames.
2. **session** — every frame afterwards:

```
[wirelen u16 LE][seq u64 LE][ChaCha20-Poly1305 box(pad(payload))]
```

- `obf_key = HKDF-SHA256(transcript_hash, "shopot-obf-v3")`.
- `nonce12 = 0x00000000 || seq` — counter-derived, so a `(key, nonce)` pair can
  never repeat by construction.
- AAD of the box is the full plaintext header `[wirelen u16][seq u64]`: the box
  is bound to both its length and its counter.
- `seq` is a per-direction frame counter (tx on the sender, rx on the
  receiver, both starting at 0). The receiver requires strictly `seq == prev
  + 1`: replays, reordering and frame substitution are discarded (`Tampered`).
- Payload is padded to a **size class**: 128 / 256 / 512 / 1024 / 4096 / 16384
  bytes, zero padding plus a random tail of up to 1/16 of the bucket, followed
  by a trailer `[pad_len u16 LE]`. Maximum payload per frame: 16356 bytes.

**What this buys:** the wire contains no constant byte — no magic numbers, no
version strings, only uniformly random bytes and quantized lengths. A passive
DPI classifier sees noise statistically similar to a compressed binary stream.
It is traffic **mimicry**, not anonymity: a global observer still sees that two
IPs are connected (§18, §15).

## 3. Handshake (XX-like, m1 → m2 → m3)

- `chaining_key = BLAKE2s-256("shopot-hs-v3")`; transcript hash = BLAKE2s-256
  over all handshake messages.
- **m1** (A → B): `e_pub_A[32] || enc_pk_A[32]` — the initiator's static
  X25519 public key travels in the clear: the responder needs it to look up
  the contact before anything is encrypted.
- **m2** (B → A): `e_pub_B[32]`, `DH(e_A, e_B)`, `enc_pk_B[32]` inside a box,
  `DH(e_A, static_B)`, `sig_B = Ed25519(transcript)` (responder static
  signature, covers the transcript as of m2).
- **m3** (A → B): `DH(static_A, e_B)`, `sig_A = Ed25519(transcript)`.
- Both sides verify the peer signature against the **known contact bundle**.
  A MITM presenting its own keys fails verification on m2/m3 (`BadSignature`)
  and the connection is dropped.
- Additionally, the static X25519 key extracted from the m2/m3 box is compared
  with the `enc_pk` of the known bundle; mismatch closes the connection
  (`KeyMismatch`). This follows the noise-libp2p practice of validating the
  remote static after an XX handshake: the responder's signature covers the
  transcript *before* the box, so without the cross-check session keys could
  have been derived against a foreign static.
- Output: `send_key`/`recv_key` (transport AEAD, §2), `transcript_hash`, and
  via HKDF the initial ratchet chains (§5).

## 4. Session encryption (sealed frames)

TEXT envelopes are sealed a **second** time above the transport AEAD:

```
[0xA1][epoch u16 LE][counter u64 LE][ChaCha20-Poly1305 box]
```

AD = the full 11-byte header. The 0xA1 magic and the epoch byte make sealed
frames self-describing inside the obfuscated stream.

## 5. Message ratchet (symmetric chain + DH epochs)

Per-message keys (symmetric ratchet):

```
msg_key_i = HKDF-Expand(chain, "shopot-msg-v3" || counter_u64_LE)
chain     = HMAC-SHA256(chain, 0x02)          // advanced after use
```

Reception follows the Double Ratchet spec (signal.org, §3.5):

- `peekRecv` derives the key for the **expected** counter without advancing
  the chain; `commitRecv` advances the chain only after a successful decrypt.
  One corrupted frame can no longer desynchronize the parties.
- The counter in the frame must equal the expected one; replay and reorder
  are discarded.

DH step (post-compromise security, "epochs"):

- Every `rotate_every = 256` sent messages a side generates a **fresh**
  X25519 pair and transmits the public key in a `RATCHET_KEY` (0x44) envelope:
  `[epoch u16 LE][dh_pub[32]]`. The envelope is consumed by the session layer
  and never reaches the engine.
- On receipt of the peer's fresh public key a side generates its own fresh
  pair if needed, replies in kind, and performs
  `dhStep(peer_fresh_pub, own_fresh_secret)`. Both sides derive the same
  shared secret `DH(a_fresh, b_fresh)`, re-create both chains
  (`root = HKDF(shared, "shopot-ratchet-v3")`), increment the epoch, and reset
  the counters.
- Compromise of epoch N chains does not read epoch N+1; past `msg_key`s are
  not re-derivable.
- **Frames in flight:** the peer may send frames of the old epoch after
  shipping its `RATCHET_KEY` but before its `dhStep`. The receiver keeps a
  snapshot of the previous epoch's receive chain (`prev_recv`: epoch, chain,
  counter) and decrypts stragglers with it; their counters must strictly
  continue the old sequence. The first successfully decrypted frame of the new
  epoch kills the snapshot — stream ordering guarantees no more old-epoch
  frames. Frames of unknown or expired epochs are dropped.
- A degenerate (low-order) `dh_pub` is a protocol violation: the session is
  closed.
- Sealed-frame format and `RATCHET_KEY` are **not** compatible with pre-epoch
  cores (header grew 9 → 11 bytes): both ends must run the same core version.

Transport AEAD stays layered on top. Compromise of the transport key does not
reveal message history, and vice versa.

The engine sends TEXT only through `sendSealedText`; on reconnect the outbox
is flushed in batches: `[len][sealed] || [len][sealed] …` in one `writeAll`,
which the obfuscation layer packs into a single padded frame (coalescing).

## 6. Invitations (v2, one-way, JOIN)

Invitation code (created by the inviter, handed over out of band):

```
shopot://i/<base64url(bundle[64] || secret[16] || name_len u8 || name ≤32)>
[@host:port]            — optional direct address
@r/<host:port>          — marks the address as a relay (§15)
```

- The 16-byte `secret` is one-time, held in the inviter's memory only.
- The code holder performs exactly **one** action (accept) and is always the
  connection initiator: it dials the embedded address, or captures the
  inviter's LAN announcement.
- A responder with an unredeemed invitation accepts m1 from an unknown
  `enc_pk` as a *pending session*: the m3 signature is not verified (the
  contact is unknown), the window is 3 seconds.
- The first envelope on a pending session **must** be `JOIN` (0x40):

```
[bundle 64][name_len u8][name][sig 64][hmac 32]
```

  - `sig = Ed25519(sign_pk from the bundle) over transcript` — binds the
    claimed bundle to the keys of *this* session (a MITM cannot present
    someone else's bundle).
  - `hmac = HMAC-SHA256(invite_secret, transcript)` — proves the holder of
    the code; a relay without the secret cannot assemble it.
- On a valid JOIN: the secret is burned, the contact is added automatically,
  the session is bound to the contact id. On an invalid JOIN or timeout the
  connection is closed.
- On a pending session **any** non-JOIN envelope closes the connection; the
  core guarantees the ordering (JOIN before PROFILE).
- v1 codes (`shopot1.<base64url(bundle|name)>[@host:port]`) are still accepted
  for compatibility: mutual add by both sides.

## 7. Envelopes (inside session frames)

| Tag | Name | Fields (LE unless noted) |
|---|---|---|
| 0x10 | TEXT | `msg_id[16], ts_ms u64, body str16 ≤ 4096` |
| 0x13 | REACT | `msg_id[16], op u8 (1 add / 2 remove), codepoint u32` |
| 0x14 | BLOCK_NOTICE | `reason u8` |
| 0x15 | ACK | `msg_id[16]` |
| 0x20 | PING | `seq u32, ts_ms u64` |
| 0x21 | PONG | `seq u32, ts_peer_ms u64` |
| 0x30 | CALL_SIGNAL | `op u8 (0 offer / 1 accept / 2 reject / 3 end), call_id[16]` |
| 0x31 | CALL_AUDIO | `seq u32, data str16 ≤ 1024` |
| 0x40 | JOIN | `bundle[64], name str8 ≤ 32, sig[64], hmac[32]` |
| 0x42 | PROFILE | `name str8 ≤ 32, avatar_id[16]` |
| 0x44 | RATCHET_KEY | `epoch u16, dh_pub[32]` (consumed by session layer) |
| 0x50 | AVATAR | `avatar_id[16], data str16 ≤ 16000` |
| 0x51 | AVATAR_ACK | `avatar_id[16]` |
| 0x52 | AVATAR_REQ | `avatar_id[16]` |
| 0x60 | FILE_META | `file_id[16], name str8 ≤ 64, size u32, sha[32]` |
| 0x61 | FILE_DATA | `file_id[16], seq u32, data str16 ≤ 16000` |
| 0x62 | FILE_ACK | `file_id[16], got u32` |

All envelope structs live in `proto/envelope.zig`; the codec performs zero
allocations (encode/decode into caller buffers).

## 8. Offline delivery (outbox)

- No session → TEXT is not an error: it goes to the outbox (memory + a sealed
  `OUTBOX` record in the encrypted log; zero plaintext on disk).
- Session up (announcement, autodial, manual connect) → the core sends all
  non-ACKed records in **batches of 64** envelopes (coalescing, §5). A replay
  after reconnect is idempotent thanks to dedup.
- Dedup: the receiver keeps a window of the last 64 `msg_id`s per contact; a
  duplicate TEXT is dropped and its ACK is mirrored again.
- ACK (0x15) is sent by the receiver of **every** TEXT: the `msg_id` clears
  the sender's outbox record; the application gets a "delivered" event.
- Outbox capacity: 1000 records, oldest evicted; TTL 30 days.
- Autodial of offline contacts to the last known address (from the invite or
  a LAN announcement): backoff 1 s → 60 s with jitter. The first LAN
  announcement is sent immediately on daemon start, so a peer with a queued
  message learns of the return within ~RTT.
- The `ts_ms` inside TEXT is the sender's local write time and stays private
  (not wall-clock); the receiving side records its own local receive time in
  history.

## 9. File transfer (resumable)

- `FILE_META` (0x60) announces the file: content-addressed
  `file_id = SHA-256(data)[0..16]`, name ≤ 64 bytes, size ≤ 64 MB, full
  SHA-256. The receiver answers **every** FILE_META with a positional
  `FILE_ACK` (0x62): `got` = how many chunks it already has — 0 for a fresh
  receive, `total` for a file already in cache (short-circuit).
- `FILE_DATA` (0x61): `seq` starts at 0, ≤ 16000 bytes per chunk (one obf
  frame of the 16384 class). The receiver stores strictly in order; a gap is
  not re-requested (the sender's window catches up by itself).
- FILE_ACK every 8 chunks plus a final one: `got` is the resume point. The
  sender keeps a window of 64 unacknowledged chunks (~1 MB) and the transfer
  state until full acknowledgement — the outbox equivalent for files.
  Transfers without a live session are queued and flushed when a session
  appears.
- Session break and reconnect: the sender re-announces FILE_META with its
  `last_ack` position; the receiver's positional reply sets the resume point
  (0 → from scratch, `total` → already complete). A reply `got < last_ack` in
  normal operation means the receiver reset its receive (SHA mismatch) — the
  transfer restarts from zero.
- All chunks acknowledged → the core clears the transfer state and raises the
  UDS event `FILE_SENT`; the receiver of a complete file raises
  `FILE_RECEIVED` (SHA check is mandatory on receipt; mismatch resets the
  receive and answers FILE_ACK 0).
- Idempotency: re-sending the same `file_id` does not duplicate the transfer
  (content addressing); receiving an already-assembled file short-circuits
  via the positional FILE_ACK. Cap: 8 concurrent transfers per peer.
- Received files are stored at `~/.shopot/files/<id_hex>` (mode 0600).

## 10. Calls (voice)

- Audio: PCM s16le mono 16 kHz, 20 ms frames → 640 bytes. IMA-ADPCM 4:1 →
  164-byte blocks (72 kbit/s). CALL_AUDIO payload: `[codec u8][block]`,
  codec 1 = PCM (640), 2 = ADPCM (164). Silence (DTX): 1 of 25 frames is sent
  as keepalive.
- Every audio frame is encrypted twice:
  1. transport AEAD (§2);
  2. per-frame call key: `key_i = HKDF-Expand(call_secret,
     "shopot-call-v3" || seq_u32_LE)`, where
     `call_secret = HKDF(transcript_hash || call_id[16], "shopot-call-v3")`.
  - A key per `seq` is used exactly once; no seq journal is stored — a replayed
    seq is discarded by the receiver (separate state machine, window 64).
  - Net effect: compromising any single layer does not yield past call frames
    (forward secrecy per frame).
- Jitter buffer: the receiver queues frames into 16 slots, playback on a
  20 ms tick — at least 3 buffered frames or 60 ms elapsed before start;
  8+ queued → drain; a 200 ms hole → skip seq (loss concealment). Induced
  latency: ~40–60 ms.
- Audio I/O runs through FIFOs `~/.shopot/pcm/mic` and `~/.shopot/pcm/spk`
  (the core reads/writes raw PCM); volume control and AGC belong to the
  client, not the core.

## 11. Presence

- Online = live connection + inbound frame timestamps. Any inbound frame
  updates `last_seen_ms` passively (zero dedicated requests).
- Only after 4 s of silence a PING is sent: 13 bytes of payload (tag + seq
  u32 + ts u64), 15 bytes on the wire with the frame header; PONG mirrors it.
- 3 missed 5 s intervals → offline. A vanished peer is probed with
  increasing rarity: 5 s → 10 → 20 → 40 → 60 s (cap). No broadcasts, no
  polling intervals.
- Precision: millisecond timestamps in every PING/PONG and TEXT.

## 12. Blocking

`BLOCK_NOTICE` (0x14) informs the peer that it has been blocked. Locally,
records from a blocked contact are dropped before envelope dispatch. The
block list lives in the encrypted log (kind `BLOCK`).

## 13. Storage

Append-only encrypted log (replaces any database):

```
header (12 B): [version u8 = 3][reserved u8 ×3][epoch u32][base_seq u32]
record:        [len u16][nonce12][ChaCha20-Poly1305 box]
nonce          = 0x00000000 || epoch_u32 || seq_u32   (deterministic)
plaintext box  = [kind u8][seq u32][payload]
storage_key    = HKDF-SHA256(Expand(HKDF-Extract("shopot-store-v3", seed), "", 32))
```

- AAD of every box is the `epoch u32 LE` of the file the record lives in —
  records cannot be transplanted between epochs.
- Record kinds and payload layouts:

| kind | value | payload |
|---|---|---|
| msg | 1 | `[cid u16][flags u8 (bit0 mine, bit1 delivered)][msg_id 16][ts u64][len u16][body]` |
| contact | 2 | contact record (bundle, name, addresses) |
| block | 3 | blocked contact |
| react | 4 | reaction record |
| set | 5 | `[key u8][value]`: 1 = my `avatar_id[16]`, 2 = my name |
| tombstone | 6 | `u32 LE` seq of the record to delete |
| outbox | 7 | sub u8: 1 = `[cid u16][msg_id 16][ts u64][len u16][body]`, 0 = `[cid u16][msg_id 16]` (delivered, clear on restart) |
| avatar | 8 | `[avatar_id 16][len u16][data ≤ 16000]` |
| file | 9 | `[cid u16][file_id 16][size u32][len u8][name]` |

- A tombstone marks a record dead in the index; compaction rewrites live
  records into a new file with `epoch+1` and drops tombstones and dead
  records.
- Any structural anomaly or failed box authentication on read → the whole
  file is untrusted (`Corrupt`).
- Not one byte of plaintext, names, or metadata touches the disk. The
  storage key is held in memory and wiped on `deinit`.

## 14. Profiles and avatars

- `PROFILE` (0x42) is echoed at every session establishment: current name +
  current `avatar_id`.
- `avatar_id = SHA-256(image)[0..16]` — content addressing: free dedup, a new
  picture = new id. Avatar bytes (≤ 16000, one obf frame of the 16384 class)
  travel only inside the E2E session, stored sealed (log kind `AVATAR`).
- Self-healing: the receiver sees a PROFILE id with no local cache → sends
  `AVATAR_REQ` (0x52) → the owner re-uploads `AVATAR` (0x50), acknowledged by
  `AVATAR_ACK` (0x51); receipt verifies SHA-256 against the id.
- The 16000-byte cap is a deliberate deviation from 32K: 32K does not fit one
  frame. Rate limit on receive: one avatar per 5 minutes (anti-spam).
- An image is untrusted binary; decoding is the client's job — the core never
  parses picture bytes. Downscaling to 128×128 is the sender client's
  responsibility; the core only rejects over-limit payloads.

## 15. Relay (IP hiding)

Self-hosted byte-split (`shopot relay <host:port>` on any server): zero
shopot state, zero crypto of its own (E2EE is end-to-end; the relay sees a
TLS-like noise stream). Both sides are relay *clients*:

```
client → relay: [17 03 03 0020][marker 32]     (TLS-like record)
relay → both:  [17 03 03 0001 5A]              (paired)
then:          transparent byte split (fake-TLS stream passes through)
```

- Two kinds of marker, both `HMAC-SHA256` over a shared secret:
  - invite phase: `HMAC(invite_secret, "shopot-relay-v1")` — computed by both
    invitation sides; the relay only compares values (one-time, burned on JOIN);
  - presence phase: `HMAC(pair_secret, "shopot-relay-presence-v1")`, where
    `pair_secret = X25519(my_static_enc, peer_static_enc)` — the Noise-KK-style
    pre-message `ss`: both sides derive it from long-term identity keys with
    zero exchanges; the relay cannot compute it.
- Slot semantics: the first connection with a marker "owns" the slot, the
  second is paired; while a pair is active extra connections are closed.
  When the pair ends the slot is **freed** — either side can re-register and
  re-pair (this is what makes presence work).
- Invite code with relay: `shopot://i/<b64>@r/<host:port>`.
- The A side (`invite <name> relay <addr>`) keeps its registration and
  reconnects on break until the invite is redeemed; the B side (`add <code>`)
  dials the relay with the marker, then the normal handshake+JOIN runs over
  the split.
- Persistent presence after JOIN: the contact remembers the relay address
  (stored in the encrypted contact log — survives daemon restarts) and the
  presence loop re-registers the slot with the contact-level marker whenever
  no live session exists. When the peer appears, the relay pairs the two and
  a fresh session runs — **no new invite needed**. The handshake role is
  deterministic: the side with the lexicographically smaller bundle
  initiates. Blocking a contact stops its presence; unblocking restores it.
- Note: static-static X25519 compromise reveals the marker (relay-side DoS /
  pairing annoyance only — the full XX handshake still authenticates); a
  compromised identity key is game-over anyway.
- The relay does **not** hide addresses from the relay itself; a DPI sees a
  TLS-like stream to the relay and back.

## 16. Fake-TLS (wire mimicry)

The whole TCP stream (m1/m2/m3 + obfuscated frames) is wrapped in a TLS-like
envelope: first an imitated handshake (ClientHello with a random SNI from a
list of unremarkable domains / ServerHello + CCS + Finished), then data as
records `[17 03 03 len u16 BE][bytes]` up to 16384 per record — record
headers big-endian, as in real TLS.

This defeats passive DPI classification only. It is **not** real TLS: an
active MITM that terminates the connection sees the forgery. IP hiding and
IP-whitelist bypass are the relay's job (§15).

## 17. Core API (UDS)

`shopot serve` exposes the UDS socket `$HOME/.shopot/api.sock` (0700) with a
binary framed protocol — the only interface of the core; GUI clients talk to
it. Frame layout, methods, machine-readable statuses, events and scenarios:
**[CORE-API.md](CORE-API.md)** (API version 1.0.0).

## 18. What an observer can learn

Honest limits of the design:

| Observer | Learns |
|---|---|
| on-path DPI | a TLS-like stream with quantized sizes (§16); no protocol markers |
| passive network observer | the *fact* that two IPs talk, volume, timing |
| relay (self-hosted) | both endpoint IPs, volume, timing; no content |
| contact | everything you send them, delivery confirmations, your current name/avatar |
| anyone with the device | the seed → identity → decrypted history |
| global adversary correlating traffic | endpoints of every connection (no cover traffic, no mixing) |

Not covered: metadata protection at network scale, denial of service,
compromise of the operating system, multi-device identity (one identity = one
live instance by design).

## 19. Versioning and compatibility

- The wire protocol is versioned by the **version byte** bound into the
  handshake transcript and the storage header (both = 3).
- Incompatible changes require bumping the version byte and an entry in
  [CHANGELOG.md](../CHANGELOG.md). No silent redefinition of existing fields.
- A major change of the UDS API contract (CORE-API.md) increments the API
  major version returned by `GET_VERSION`.
- Sealed frames (0xA1 + epoch header) and `RATCHET_KEY` are incompatible with
  pre-epoch cores: both ends must run the same core version.
