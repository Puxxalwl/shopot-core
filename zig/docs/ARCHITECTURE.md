# Architecture (zig core)

Layer and data-flow reference for the `shopot-zig` core. Russian version:
[ARCHITECTURE.ru.md](ARCHITECTURE.ru.md).

## 1. Principles

1. **std-only**: zero external libraries. Cryptography is composition of
   `std.crypto` primitives — never a hand-rolled primitive.
2. **Boundaries via vtable interfaces** (`core/interfaces.zig`): `Conn`
   (readAll/writeAll/close), `Transport` (dial), `Clock` (time). Layers know
   only interfaces; concrete implementations are injected (dependency
   inversion). This is what makes the core testable without sockets.
3. **Zero allocations on the hot path**: frames and envelopes encode into
   caller-provided buffers (stack where possible). An allocator is required
   only by stateful structures (log index, session map).
4. **One concern per file.** A module imports only `core/interfaces.zig`,
   never a sibling module. Integration belongs to the engine layer.

## 2. Layers (top → bottom)

| Layer | Directory | Responsibility |
|---|---|---|
| app | `src/shopot/app/` | daemon: UDS API server, invites, LAN discovery, autodial, outbox flushing, call audio loop, file transfers |
| core | `src/shopot/core/` | engine (contacts, locks, dispatch, outbox, file Tx state machines), session (handshake + sealed frames) |
| proto | `src/shopot/proto/` | binary envelopes, allocation-free codec |
| crypto | `src/shopot/crypto/` | identity, handshake, ratchet, call keys, AEAD, padding |
| net | `src/shopot/net/` | TCP transport, stream obfuscation (fake-TLS framing), relay, heartbeat |
| store | `src/shopot/store/` | encrypted append-only log |

## 3. Message data flow

```
sendText
  → engine: outbox or live session
  → envelope.encode (stack buffer)
  → [ratchet seal: 0xA1 | epoch | counter | AEAD box]
  → session: writeAll of header+payload (one obf frame per envelope,
    batches for outbox flushes)
  → obfuscation: pad to size class + ChaCha20-Poly1305 frame box
  → fake-TLS record
  → TCP
```

Receive is the mirror: `Conn.readAll` → de-frame (AAD check, seq check) →
de-obfuscate → envelope decode → `Engine.dispatch` under the engine lock →
callbacks into the app layer.

## 4. Threading model

- One **rx thread per session**; sending is serialized under the session
  mutex.
- The UDS API server accepts multiple clients; requests execute sequentially
  under the app lock; events fan out to all connections.
- Presence has no thread of its own: it is a pure state machine; time is
  injected via `Clock`, transport actions are returned to the caller.
- Call audio runs its own loop (FIFO in/out, 20 ms tick).

## 5. Error and memory model

- Every module defines its own error set. `anyerror` appears only at
  interface boundaries; `catch unreachable` only in tests.
- Every public function takes `std.mem.Allocator` where allocation is needed.
  Hot paths use stack buffers or `FixedBufferAllocator`.
- No global state. Secrets (keys, chains, seeds) are wiped with
  `std.crypto.secureZero` when their owning object dies.

## 6. Callbacks (engine → app)

The engine reports everything through function pointers set by the app:
`onText`, `onReact`, `onAck`, presence changes, `onProfile`, `onAvatar`,
`onAvatarReq`, `onFileSent`, call state. The app layer turns them into UDS
events.

## 7. Testing

- Unit tests (`test {}` blocks) live in each file and are owned by the
  module owner.
- Integration scenarios live in `tests/integration.zig`: full protocol
  between two in-process parties over loopback/scripted connections
  (handshake → messages → rotation → reconnect → resume).
- `zig build test` green is the handoff condition; CI runs it on every
  `zig-v*` tag together with release builds for x86_64-linux-musl and
  aarch64-macos.
