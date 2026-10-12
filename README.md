# shopot-core

**Serverless P2P messaging engine. No accounts. No servers. No traces anywhere but the two devices.**

shopot-core is a C++20 library that lets two users exchange text messages,
files and voice notes **directly** (WebRTC DataChannels, DTLS, peer-to-peer),
with all history stored **exclusively on the devices** in an encrypted SQLite
database. It is the engine only: desktop/mobile apps are built on top of it
(one per OS), it ships with a demo CLI for testing.

- 🔑 **The account is a 12-word mnemonic** (BIP-39). No email, no phone, no
  signup, nothing stored server-side (there is no server). New device → type
  the 12 words → same identity. History does not travel — by design it lives
  only on the device that saw the messages.
- 🔐 **End-to-end encryption with forward secrecy.** X25519 + Ed25519
  identities (libsodium), per-session ephemeral keys signed by the identity
  keys, XSalsa20-Poly1305 AEAD. Recorded traffic is worthless even if a
  device is later seized.
- 📦 **Offline delivery without any server** — the way it has to be: a message
  to an offline peer waits in the *local* encrypted outbox; when both peers
  meet online (handshake on connect), the buffer flushes and cleans itself.
- 📁 **Files of any size** stream in 16 KiB chunks with backpressure and a
  SHA-256 integrity check. Voice notes are files flagged `voice` — recording
  is the app's job (engine stays OS-free).
- 🕵️ **Metadata minimization.** The only third party ever contacted is a
  public STUN server (discovers your NAT address; sees IPs, never data, and
  can be disabled). Connection codes can be compared out-of-band via safety
  numbers to defeat MITM.

## Why "manual" signaling?

True zero-server operation means nothing out there introduces peers to each
other. So the *app* shows a short code, and the user passes it to the peer
through **any** existing channel (any messenger, QR, phone call):

```
Alice                       Bob
  |-- make_offer() ------->  |  code A (base64url, one line)
  |                          |-- handle_offer(codeA) → code B
  |<------ handle_answer --- |
  |==== encrypted P2P session established, outboxes flush ====|
```

Codes are single-use, per-connection. This is the honest price of "no servers,
period". The transport is abstracted (`IChannel`), so an app that wants
automatic rendezvous can plug in public infrastructure (Nostr relays,
BitTorrent trackers) **without touching the core** — see Roadmap.

## Build

Dependencies: CMake ≥ 3.24, a C++20 compiler, `libsodium`, `sqlite3`.
libdatachannel is fetched automatically (uses system GnuTLS on Linux).

```bash
# Arch:  sudo pacman -S libsodium sqlite cmake
# Debian/Ubuntu: sudo apt install libsodium-dev libsqlite3-dev cmake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/shopot-tests          # crypto + storage + full loopback protocol e2e
```

Options: `SHOPOT_WITH_RTC=OFF` (core only, transport-agnostic),
`SHOPOT_BUILD_CLI=OFF`, `SHOPOT_BUILD_TESTS=OFF`.

## Try it: two terminals

```bash
./build/shopot-cli --db alice.db --dl dl-alice   # pick "new", write down words
./build/shopot-cli --db bob.db   --dl dl-bob     # same
```

```
alice> bundle                     → send the bundle to Bob (any channel)
bob>   add alice <bundle>
bob>   bundle                     → send to Alice
alice> add bob <bundle>
alice> offer 1                    → code A → send to Bob
bob>   answer 1 <codeA>           → code B → send to Alice
alice> accept 1 <codeB>
     ... [1] ONLINE on both sides ...
alice> msg 1 привет               (queued if Bob were offline, delivered on meet)
bob>   send 1 /path/to/file.zip
bob>   hist 1
```

## Embedding (your app per OS)

```cpp
#include <shopot/shopot.hpp>

shopot::Config cfg;
cfg.db_path = "app.db";
cfg.download_dir = "downloads";

shopot::Events ev;
ev.on_message   = [](const shopot::Message& m){ /* render bubble */ };
ev.on_presence  = [](int64_t cid, bool online){ /* status dot */ };
ev.on_status    = [](const std::string& id, shopot::MsgStatus s){ /* ticks */ };
ev.on_file_ready= [](int64_t cid, const shopot::Message& m, const std::string& path){};

shopot::Engine engine(cfg, mnemonic, ev);

auto cid   = engine.add_contact(peer_bundle, "Alice");
auto code  = engine.make_offer(cid);            // show as QR / text
engine.handle_answer(cid, answer_code);         // when peer replies

auto msgId = engine.send_text(cid, "hi");       // safe while offline: queues
auto file  = engine.send_file(cid, "/tmp/voice.opus", "audio/ogg",
                              shopot::MsgKind::Voice);
auto hist  = engine.history(cid, 50);           // newest first
```

All callbacks fire on one serialized dispatcher thread. All API calls are
thread-safe.

## Documentation

- [docs/PROTOCOL.md](docs/PROTOCOL.md) — full wire protocol v1 spec (interoperable reimplementations)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — modules, threading, data flow, porting guide
- [SECURITY.md](SECURITY.md) — reporting, crypto inventory, hardening
- [CONTRIBUTING.md](CONTRIBUTING.md) — build, ground rules, PRs

## Protocol (v1)

| layer      | choice                                                        |
|------------|---------------------------------------------------------------|
| identity   | BIP-39 entropy → HKDF → X25519 + Ed25519 + storage key        |
| handshake  | hello: ephemeral X25519, Ed25519-signed, room-hash bound      |
| session    | XSalsa20-Poly1305, random 24-byte nonces, forward secrecy     |
| transport  | WebRTC DataChannel (reliable, ordered), STUN-only NAT traversal |
| wire       | frame type byte; JSON envelopes; binary 16 KiB chunks          |
| storage    | SQLite (WAL); every sensitive blob sealed with the storage key |
| integrity  | SHA-256 per file, verified before delivery to the app          |

Wire frames: `0x10` hello (plaintext JSON, signed) · `0x11` sealed envelope
(text / ack / file-meta / file-done) · `0x12` sealed file chunk.

## Threat model — honest version

**Defeats:** mass surveillance (E2E + forward secrecy), server breaches (no
servers), history seizure of *one* device (DB is encrypted; the key comes from
the mnemonic), account takeovers (no accounts), metadata collection (no
contacts/graph on any server).

**Does not defeat:** a compromised endpoint (nothing can), physical access to
an unlocked device, a global passive adversary correlating *timing* of the two
peers' traffic (use the Tor-pluggable transport — Roadmap), MITM during code
exchange (defeated by comparing fingerprints out-of-band).

## Roadmap

- [ ] Pluggable rendezvous (`ISignaling`): Nostr relays / BitTorrent trackers
      for automatic reconnects without code exchange
- [ ] Double Ratchet (per-message key evolution)
- [ ] File transfer resume across sessions (chunk bitmaps already stored)
- [ ] Tor onion-service transport (no STUN, no IP leakage at all)
- [ ] Voice messages: engine-level opus framing helpers
- [ ] Reference apps: Android (JNI), iOS, desktop (Qt/Tauri)

## License

MIT. Use it, fork it, ship it.
