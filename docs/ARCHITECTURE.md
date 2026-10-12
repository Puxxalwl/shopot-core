# Architecture

```
┌──────────────────────────── your app (Qt / Android / iOS / CLI) ─┐
│                     include/shopot/shopot.hpp                     │  ← entire API
├──────────────────────────────────────────────────────────────────┤
│  engine.cpp        facade, contacts, outbox, event dispatch       │
│  session.cpp       per-contact protocol state machine             │
│  transport/rtc.cpp WebRTC DataChannels + manual code signaling    │
│  transport/channel.hpp  IChannel abstraction (plug your own)      │
│  db.cpp            SQLite, every sensitive blob sealed at rest    │
│  crypto.cpp        libsodium: identity, handshake, AEAD           │
└──────────────────────────────────────────────────────────────────┘
```

## Design invariants

1. **The engine never talks to a server.** The only network I/O is the peer
   channel and (optionally) STUN address discovery.
2. **Plaintext never touches the disk layer.** `Db` receives plaintext and
   seals internally; readers open internally. App code only ever sees
   plaintext that came from the user or a verified peer.
3. **The protocol is transport-agnostic.** `Session` speaks to an
   `IChannel`; WebRTC is one implementation. The test suite runs the full
   two-party protocol over an in-memory loopback.
4. **No global state, no singletons.** An `Engine` instance is one unlocked
   identity on one database file.

## Threading

| thread                    | role                                                        |
|---------------------------|-------------------------------------------------------------|
| caller threads            | any API method (all are thread-safe)                        |
| libdatachannel threads    | ICE/DTLS/SCTP; invoke channel callbacks                     |
| one tx thread per Session | ordered sending, file pumping with backpressure             |
| one dispatcher per Engine | all user callbacks fire here, serialized                    |

Locking discipline: `Session::mu_` guards only the session crypto state;
SQLite is compiled serialized and protected by `busy_timeout`; the engine's
`mu_` guards the session map. No lock is held while user callbacks run.

## Send path (text, peer offline)

```
app → Engine::send_text
      ├─ messages row (status=queued, body sealed)
      └─ outbox row (envelope JSON, sealed)
        … peer appears …
Session handshake ok → kick() → tx thread:
      outbox rows → seal with SESSION key → 0x11 frames → status=sent
      ack returns → outbox row deleted → status=delivered
```

## Receive path (file)

```
0x11 "file" envelope → files row (receiving) + message row + ack
0x12 chunks          → open (session key) → seal (storage key) → chunks table
last chunk           → reassemble → SHA-256 verify → download dir
                     → fdone to sender → on_file_ready to app
```

Chunks of an interrupted transfer stay sealed in the DB; a retry overwrites
them idempotently (v1 restarts from chunk 0 — resume is roadmap).

## Failure model

| failure                       | behaviour                                            |
|-------------------------------|------------------------------------------------------|
| channel dies mid-transfer     | session closed, presence off; outbox intact; retry on next connect |
| forged/corrupt frame          | authentication failure → dropped silently            |
| bad handshake signature       | session never establishes; error event               |
| wrong mnemonic at unlock      | DB open succeeds, first read fails authentication    |
| app crash                     | WAL recovery; outbox/files resume from DB state      |

## Porting guide (writing an OS app)

1. Link `shopot-core`, call `Engine::generate_mnemonic()` on first run.
2. Persist the mnemonic in the OS keychain (or demand it per launch).
3. Map `Events` to your UI; everything arrives on one dispatcher thread.
4. Signaling UI: `make_offer`/`handle_offer`/`handle_answer` — render
   codes as copyable text or QR.
5. Voice notes: record with the OS audio API (Opus recommended), then
   `send_file(..., MsgKind::Voice)`.
6. Respect the platform lifecycle: `Engine` destructor closes sessions
   cleanly; on mobile, disconnect in background, reconnect in foreground.
