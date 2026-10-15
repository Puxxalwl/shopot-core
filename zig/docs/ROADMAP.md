# ROADMAP — shopot-core technical plan

Priorities for agents and client authors. Everything is std-only: no OS
packages, no external services. Order = recommended implementation order.
Russian version: [ROADMAP.ru.md](ROADMAP.ru.md).

## P0 — ✅ DONE

- ~~Relay~~: `shopot relay` + `invite <name> relay <addr>` — HMAC
  marker-pairing (invite secret), byte split, A-side self-reconnect
  (e2e: E2E-RELAY-PASS).
- ~~Fake-TLS~~: wire disguised as TLS 1.3.
- ~~Call jitter buffer~~: 16-slot queue, 20 ms playback tick.
- ~~Calls 16 kHz + ADPCM + DTX~~: 72 kbit/s.
- ~~Chunked files~~: FILE_META/FILE_DATA, SHA verification, dedup.

Remaining from P0: persistent relay presence of a contact (reconnecting
through a relay after JOIN currently requires a new invite).

## P0+ — ✅ DONE: ratchet PCS rotation

- ~~In-session DH step~~ ✅: `RATCHET_KEY` (0x44) exchanges fresh X25519
  public keys; both sides run `dhStep` every `rotate_every = 256` messages;
  sealed frames carry the epoch (`[0xA1][epoch u16][counter u64][box]`);
  in-flight frames of the previous epoch decrypt via the `prev_recv`
  snapshot, killed by the first new-epoch frame. A full skipped-keys window
  per spec §2.6 is unnecessary: stream ordering (obf/TCP) guarantees strictly
  sequential frames, dedup by counter. E2E: 48 messages at threshold 4, no
  losses, epochs equal on both sides.

## P0+ — next after the relay

Fake-TLS hides the protocol from DPI; the relay hides the IP. What remains:

- **Relay presence**: the contact stores the relay address and keeps its
  registration (marker = HMAC over a long-lived contact-level secret),
  reconnecting without a new invite. The invite secret is currently
  one-time — a contact-level secret is needed.
- **Multi-relay**: an invite with several addresses (failover).

## P0 — calls: quality

- **Jitter buffer** (adaptive, 2–5 frames): frames currently play
  immediately; network jitter → clicks. Buffer in onCallAudioEv + a drain
  timer.
- **Audio resume**: DTX already sends keepalive; add comfort noise (light
  noise generation during silence).
- **Opus is out** (external codec) — alternative: two-level ADPCM (highs
  encoded by a second block) or an SBC-like sub-codec, ~14 kbit/s. Lower
  priority: 72 kbit/s is already fine for voice.
- Volume/AGC — client-side (GUI); the core does not touch it.

## P1 — file transfer: resume

- ✅ **FILE_ACK** `{file_id, got u32}`: the receiver acknowledges every 8th
  chunk (+ the final one, and a positional reply to every FILE_META); the
  sender keeps a 64-chunk window (~1 MB) and resumes from the last ACK on
  session break — the transfer auto-resumes on reconnect (engine.file_tx,
  resumeFileTx + FILE_SENT UDS event). E2E "resume after break" in
  tests/integration.zig.
- File list over UDS: `files <cid>` → `f <id_hex> <size> <name>` (FILE log
  records are already written).
- Content retrieval: `getfile <id_hex> <path>` — a copy from the cache.
- Chunks > 16000 (up to 64000) per envelope: fewer frames for large files
  (obf still splits into 16356-byte frames) — measure the win first.

## P1 — performance

- ~~Small-envelope coalescing~~ ✅: header+payload in one writeAll (one obf
  frame per envelope instead of two); outbox/TEXT batches via
  sendSealedTexts — one frame per batch. Optional next: coalescing
  REACT/ACK/PROFILE into a shared batch writer.
- **zlib compression** of payloads > 512 bytes before AEAD
  (std.compress.flate): text compresses 2–4×, random data does not —
  header flag. Do not compress PNG/JPG avatars/files (magic-byte detect).
- FBA on hot paths envIn/dispatch (AGENTS.md §3): currently a couple of
  allocations per envelope. Measure first, then fix pointwise.

## P2 — API conveniences

- `search <query>` — history search (MSG log is already decrypted by
  readAll(.msg)).
- Group chats = N pairwise sessions + fan-out by the engine (no new
  envelopes, delivery logic only). Ask first whether it is needed.
- `typing` indicator: empty envelope (tag TBD — 0x62 is taken by FILE_ACK),
  UDS event `typing <cid>` + a 3 s timeout.
- History export: `export <cid> <path>` — text dump from the log.

## Anti-plan (do NOT build)

- ❌ External dependencies (opus/libsodium/zlib-ng) — std only.
- ❌ JSON over UDS — the binary frame protocol stays.
- ❌ "Cloud" sync — serverless architecture; keys live with the users only.
- ❌ Multi-device: one identity = one live instance (as of now; multi-device
  requires ratchet forwarding — a separate large project).
