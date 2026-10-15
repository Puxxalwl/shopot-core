# shopot

**English** | [Русский](docs/ru/README.md)

Serverless P2P messenger core: **zero servers of our own**, message history
lives on the two devices only. Implementation: pure Zig, std-only — no
packages, no OS dependencies. Source: [`zig/`](zig/).

The C++ version (v0.2.4, FTXUI/MQTT/WebRTC) is removed from master; the
archive lives under the tag `cpp-archive`.

## Feature set

| Area | What the core does |
|---|---|
| Identity | X25519 + Ed25519 keypairs derived from one 32-byte seed (`~/.shopot/zig-seed`, 0600) |
| Transport | Direct TCP (ports 7777–7786) or self-hosted relay; LAN discovery over UDP multicast; wire disguised as TLS 1.3 |
| Encryption | XX-like handshake, AEAD transport, double ratchet with post-compromise security (epoch rotation every 256 messages) |
| Messaging | Offline delivery (encrypted outbox, ACKs, dedup), reactions, 16 kHz E2EE voice calls (ADPCM, DTX), resumable file transfer |
| Storage | Append-only AEAD log — zero plaintext bytes on disk |
| Interface | Binary framed UDS API (`~/.shopot/api.sock`) — the only interface; GUI clients render, the core does everything else |

## Build

Requires [Zig 0.17.0](https://ziglang.org/download/) only.

```bash
make            # = cd zig && zig build -Doptimize=ReleaseFast
make test       # = cd zig && zig build test --summary all
```

Binary: `zig/zig-out/bin/shopot-zig`. Release builds for
x86_64-linux-musl and aarch64-macos are attached to every `zig-v*` tag.

## Running

```bash
shopot-zig init          # identity: ~/.shopot/zig-seed (0600)
shopot-zig serve         # daemon: core + UDS API (~/.shopot/api.sock)
```

There is no CLI/TUI: the only client interface is the GUI, which talks to
the core over UDS using the binary framed protocol (typed responses,
machine error codes, events). Specification for client authors:
[`zig/docs/CORE-API.md`](zig/docs/CORE-API.md) (API 1.0.0).

Adding a friend is one action: `CREATE_INVITE` produces a one-way code
(`shopot://i/...`); the holder performs a single `ACCEPT_INVITE`. The
contact, session and delivery are established by the core itself (LAN
discovery, autodial, offline outbox, delivery ACKs).

## Relay (IP hiding)

```bash
# on any server (VPS):
./shopot relay 0.0.0.0:9000

# on your side:
> invite bob relay vps.example.com:9000
# → the code goes to bob; bob accepts it and sees only the relay address
```

## Cryptography

- XX-like handshake (X25519 + Ed25519, transcript signatures, remote-static
  verification)
- Double encryption of messages: ratchet chains on top of an AEAD stream
- Calls: 20 ms frames, per-frame key = HKDF(call_secret, seq), own AEAD
  transport
- Storage: append-only AEAD log, not a single plaintext byte

Details: [`zig/docs/PROTOCOL.md`](zig/docs/PROTOCOL.md),
[SECURITY.md](SECURITY.md).

## Documentation

| Document | Content |
|---|---|
| [`zig/docs/CORE-API.md`](zig/docs/CORE-API.md) / [ru](zig/docs/ru/CORE-API.md) | binary UDS interface for GUI clients (API 1.0.0) |
| [`zig/docs/PROTOCOL.md`](zig/docs/PROTOCOL.md) / [ru](zig/docs/ru/PROTOCOL.md) | byte-level wire protocol v3 |
| [`zig/docs/ARCHITECTURE.md`](zig/docs/ARCHITECTURE.md) / [ru](zig/docs/ru/ARCHITECTURE.md) | layers, data flow, threading |
| [`zig/docs/ROADMAP.md`](zig/docs/ROADMAP.md) / [ru](zig/docs/ru/ROADMAP.md) | technical plan and anti-plan |
| [SECURITY.md](SECURITY.md) / [ru](docs/ru/SECURITY.md) | threat model, reporting, crypto inventory |
| [CONTRIBUTING.md](CONTRIBUTING.md) / [ru](docs/ru/CONTRIBUTING.md) | contribution rules (kernel-style) |

## Official client

- Second project developer: [EryyynIT](https://github.com/EryyynIT)
- Official shopot client: [shopot](https://github.com/EryyynIT/shopot)

## License

MIT — see [LICENSE](LICENSE).
