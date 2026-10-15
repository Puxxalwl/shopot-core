# CORE-API — shopot core binary interface

Technical specification for GUI client authors. Russian version:
[ru/CORE-API.md](ru/CORE-API.md).

The core (the `shopot serve` daemon) owns the cryptography, contacts,
sessions, and delivery. A client connects over a Unix domain socket and
renders. The protocol is **binary**: no strings-as-protocol, no JSON, no
human-readable text on the wire — only typed byte frames and machine-readable
codes (methods, statuses, events).

- API version: **1.0.0** (returned by `GET_VERSION`, semver).
- Normative wire protocol: [PROTOCOL.md](PROTOCOL.md).

## 1. Model

| Entity | Definition |
|---|---|
| core | the `shopot serve` process. One user = one daemon = one `$HOME`; several users on a machine use different `$HOME`s |
| client | any process connected to `$HOME/.shopot/api.sock` (UDS, mode 0700). Multiple concurrent connections are allowed; events are broadcast to all |
| contact | the conversation peer, identified by its bundle (`enc_pk‖sign_pk`, 64 bytes). In this API a contact is an integer `cid` (u32), stable within a given `$HOME`: 1..N in order of addition |
| msg_id | 16 random bytes identifying a message globally; used for reactions, statuses, `GET_MESSAGE` |

The core has no TUI/CLI: the daemon has no interactive input; all control
flows through this API.

### One user action maximum

The core owns: introductions (JOIN protocol), address discovery (LAN
multicast, autodial), offline delivery (outbox + ACK), reconnection,
presence. For the user, any scenario is zero or one action (paste an invite
code). A client must not ask for confirmations, addresses, or an ordering of
steps — the core has already handled them.

### What the core does NOT do

- UI, rendering, emoji glyphs, QR — client's job.
- Third-party storage — there is none; content lives on the two devices only
  (the encrypted log is local).
- NAT traversal for two NAT-ed peers: the channel is LAN, direct TCP
  (auto-selected port range 7777–7786), or a relay (`shopot relay` on any
  server).
- Parsing pictures/files: bytes are passed as-is.

## 2. Frame

All integers are little-endian. The header of every frame is exactly 16 bytes:

| Field | Type | Offset | Meaning |
|---|---|---|---|
| magic | u16 | 0..2 | `0x5A50` ("ZP") |
| version | u8 | 2 | `1` |
| kind | u8 | 3 | `1` = REQUEST, `2` = RESPONSE, `3` = EVENT |
| id | u16 | 4..6 | method (REQUEST/RESPONSE) or event (EVENT) |
| request_id | u32 | 6..10 | correlation: set by the client, echoed by the core in RESPONSE; `0` in EVENT |
| status | u16 | 10..12 | status code (RESPONSE only; `0` otherwise) |
| payload_len | u32 | 12..16 | payload length, `0..1048576` (1 MiB) |

- Exactly one REQUEST yields exactly one RESPONSE with the same `id` and
  `request_id`.
- Payload over 1 MiB → `TOO_BIG` and the connection is dropped.
- Broken magic/version, or a non-REQUEST frame from a client → `BAD_FRAME`
  and the connection is closed (stream resynchronization is impossible).
- There are no text fields. Strings are `str16` = `[len u16][bytes]` and
  `str32` = `[len u32][bytes]` (raw UTF-8 bytes, no terminator).
- Extra or missing bytes in a method payload → `BAD_FRAME` (strict parsing).
- `CLOSE` closes the connection (not the daemon).

## 3. Status codes

Names are the contract. There is and will be no human-readable text in
responses.

| Code | Name | When |
|---|---|---|
| 0 | `OK` | success |
| 1 | `BAD_FRAME` | frame/payload not parsed (magic, version, length, structure) |
| 2 | `UNKNOWN_METHOD` | unknown method id |
| 3 | `BAD_ARGS` | invalid/incomplete argument values |
| 4 | `NO_CONTACT` | cid does not exist |
| 5 | `CONTACT_BLOCKED` | contact is blocked locally |
| 6 | `NOT_FOUND` | object not found (message by msg_id) |
| 7 | `TOO_BIG` | size limit exceeded (body, avatar, frame, history) |
| 8 | `BAD_INVITE_CODE` | invite code not parsed/recognized |
| 9 | `TOO_MANY_INVITES` | invite registry full (4 live) |
| 10 | `FILE_NOT_FOUND` | file at path not found/not readable |
| 11 | `UNSUPPORTED_REACTION` | reaction codepoint outside U+0000..U+10FFFF |
| 12 | `NO_SESSION` | no live session with the contact (required for the operation) |
| 13 | `BUSY` | line is busy (a call is already active) |
| 14 | `NO_CALL` | no active call |
| 15 | `NO_RELAY` | relay unreachable |
| 16 | `TRANSPORT_FAILED` | transport did not come up (dial/handshake) |
| 255 | `INTERNAL` | internal core error |

## 4. Methods (REQUEST)

Names are the contract; values are stable. "∅" — empty payload.

### 4.1 Service

| Method | id | Payload | Response (payload at OK) |
|---|---|---|---|
| `GET_VERSION` | 2 | ∅ | `[major u16][minor u16][patch u16]` |
| `GET_IDENTITY` | 3 | ∅ | `[bundle 64][fingerprint 32]` — BLAKE2s-256(bundle), raw bytes |
| `CLOSE` | 1 | ∅ | ∅, then the core closes the connection |

`GET_VERSION` is the readiness probe: connect → `GET_VERSION` → proceed.
A major bump means this document's contract changed (see CHANGELOG).

### 4.2 Contacts

#### `CREATE_INVITE` (4)
Payload: `[flags u8 (bit0 = relay)][name str16 ≤ 32][addr str16]`.
- Empty name → `shopot`. `addr` is `host:port` (optional: otherwise the holder
  discovers the inviter via the LAN announcement). `relay=1` requires `addr`;
  the connection goes through a relay — the peer never sees your IP.
- The secret is one-time: burned by the first valid JOIN. Registry: up to 4
  live invites in daemon memory (a restart invalidates the codes).

Response: `[code str16]` — the one-way invite code (URL
`shopot://i/...`, transferable over any messenger; v1 codes `shopot1.` are
also accepted).
Errors: `TOO_MANY_INVITES`, `BAD_ARGS`.

#### `ACCEPT_INVITE` (5)
Payload: `[code str16][my_name str16]`. The **only** action of the code
holder.
- `my_name` (≤ 32, empty → `друг`) is what the inviter will see.
- A code with an address connects immediately; without one, the core waits
  for the inviter's LAN announcement / autodials.
- Connection status arrives via `PRESENCE` events (establishment is async).

Response: `[cid u32]`. Errors: `BAD_INVITE_CODE`, `BAD_ARGS`.

#### `LIST_CONTACTS` (6)
Payload: ∅. Response:
```
[count u32]
× { [cid u32][flags u8 (bit0 online, bit1 blocked)][last_seen_ms i64 (0 = unknown)][name str16] }
```

### 4.3 Messages

#### `SEND_MESSAGE` (7)
Payload: `[cid u32][body str16 ≤ 4096]`.
Response: `[msg_id 16][flags u8 (bit0 = queued)]`.
- Sending to an offline contact is NOT an error: `queued=1` — the message
  leaves when the contact appears (outbox; confirmation is the
  `MESSAGE_DELIVERED` event).
- Errors: `NO_CONTACT`, `CONTACT_BLOCKED`, `BAD_ARGS` (empty body).

#### `SET_REACTION` (8) / `REMOVE_REACTION` (9)
Payload: `[cid u32][msg_id 16][codepoint u32]`.
- The codepoint is a Unicode code point, U+0000..U+10FFFF; outside the range
  → `UNSUPPORTED_REACTION`. A reaction requires a live session.
- Response: ∅. Errors: `NO_CONTACT`, `NO_SESSION`, `UNSUPPORTED_REACTION`,
  `CONTACT_BLOCKED`.
- Local reaction history records only additions (removal is sent to the peer
  but not logged — v1).

#### `GET_HISTORY` (10)
Payload: `[cid u32][limit u32]` (0 → 50; maximum 200 → `TOO_BIG`).
Response:
```
[total u32]   — total records for the contact
[count u32]
× { [flags u8 (bit0 mine, bit1 delivered)][msg_id 16][ts_ms u64][body str16] }
```
Records oldest → newest. `ts_ms` is local record time (ms, epoch). Stored in
the encrypted log, survives restarts. No log → empty list
(`total=0, count=0`).

#### `GET_MESSAGE` (11)
Payload: `[msg_id 16]`. Response:
```
[cid u32][flags u8 (bit0 mine, bit1 delivered)][ts_ms u64][body str16]
[react_count u32]
× { [flags u8 (bit0 mine)][codepoint u32][ts_ms u64] }
```
No record → `NOT_FOUND`.

### 4.4 Own profile

#### `SET_NAME` (12)
Payload: `[name str16 1..32]`. Response: ∅. Sent to peers in PROFILE (online
— immediately; offline — at the next session).

#### `SET_AVATAR` (13)
Payload: `[data str32 1..16000]` — image bytes inline (format is not parsed
by the core). Response: `[avatar_id 16][size u32]`.
- `avatar_id = SHA-256(data)[0..16]` — content addressing.
- Storage: encrypted log, survives restarts.

#### `GET_AVATAR_ID` (14)
Payload: `[cid u32]`. Response: `[avatar_id 16]` (all zeros — no avatar).
The bytes themselves arrive as the `AVATAR_RECEIVED` event: the core requests
them itself (AVATAR_REQ) on an id mismatch and self-heals on reconnect — the
client only listens for the event and caches by id.

### 4.5 Files

#### `SEND_FILE` (15)
Payload: `[cid u32][path str16]` — a path in the daemon user's filesystem
(the client drops the file, e.g., into `$HOME/.shopot/tmp/`, and passes the
path).
- Limit 64 MB. Without a live session the transfer is queued (outbox
  semantics) and flushed when a session appears.
- The name is taken from the path (basename, ≤ 64 bytes).

Response: `[file_id 16][size u32][chunks u32]`.
- `file_id = SHA-256(file)[0..16]`; the receiver verifies the hash and stores
  the file at `~/.shopot/files/<hex>` (0600). A duplicate is not re-sent.
- The receiver gets the `FILE_RECEIVED` event; the sender gets `FILE_SENT`
  when all chunks are acknowledged.
- Errors: `NO_CONTACT`, `FILE_NOT_FOUND`, `TOO_BIG`, `BAD_ARGS`.

### 4.6 Calls

| Method | id | Payload | Response |
|---|---|---|---|
| `START_CALL` | 16 | `[cid u32]` | `[call_id 16]` |
| `ANSWER_CALL` | 17 | ∅ | ∅ |
| `END_CALL` | 18 | ∅ | ∅ |

- Voice: 16 kHz mono, E2EE, IMA-ADPCM 4:1, DTX (see PROTOCOL.md §10).
- One line per daemon: `START_CALL` during an active call → `BUSY`;
  `ANSWER/END` without a call → `NO_CALL`. `START_CALL` without a session →
  `NO_SESSION`.
- Audio flows through the FIFOs `~/.shopot/pcm/mic` and `~/.shopot/pcm/spk`
  (the core reads/writes).
- State changes arrive as `CALL_STATE` events.

### 4.7 Blocking and transport

| Method | id | Payload | Response |
|---|---|---|---|
| `BLOCK_CONTACT` | 19 | `[cid u32]` | ∅ |
| `UNBLOCK_CONTACT` | 20 | `[cid u32]` | ∅ |
| `CONNECT` | 21 | `[cid u32][addr str16]` | ∅ |
| `LISTEN` | 22 | `[addr str16][cid u32]` | ∅ |

`BLOCK_CONTACT`: traffic is dropped, the peer is notified. `CONNECT`/`LISTEN`
are normally unnecessary (autodial/LAN handle it); errors — `NO_CONTACT`,
`TRANSPORT_FAILED`, `NO_RELAY`.

## 5. Events (EVENT)

Broadcast to all connected clients, in any order, `request_id = 0`.

| Name | id | Payload |
|---|---|---|
| `MESSAGE_RECEIVED` | 1 | `[cid u32][msg_id 16][ts_ms u64][name str16][body str16]` |
| `MESSAGE_DELIVERED` | 2 | `[cid u32][msg_id 16]` |
| `PRESENCE` | 3 | `[cid u32][online u8 (1/0)][last_seen_ms i64]` |
| `REACTION` | 4 | `[cid u32][msg_id 16][op u8 (1 = add, 2 = remove)][codepoint u32][ts_ms u64]` |
| `CALL_STATE` | 5 | `[cid u32][call_id 16][state u8 (1 offer, 2 accept, 3 reject, 4 end)]` |
| `AVATAR_RECEIVED` | 6 | `[cid u32][avatar_id 16][data str16 ≤ 16000]` |
| `FILE_RECEIVED` | 7 | `[cid u32][file_id 16][size u32][name str16]` |
| `CONTACT_JOINED` | 8 | `[cid u32][name str16]` |
| `CONTACT_PROFILE` | 9 | `[cid u32][name str16][avatar_id 16]` |
| `BLOCKED_BY_PEER` | 10 | `[cid u32]` |
| `FILE_SENT` | 11 | `[cid u32][file_id 16][size u32][name str16]` |

- `MESSAGE_RECEIVED.ts_ms` = local receive time, consistent with GET_HISTORY
  timestamps. The `msg_id` is what reactions address.
- `PRESENCE`: render the online status from this event only — do not poll.
- `CALL_STATE`: reject/end always terminate the audio loop (after reject, an
  end follows too).
- `CONTACT_JOINED`: the holder of your invite has connected — the contact
  exists now.
- `CONTACT_PROFILE`: the contact's name/avatar_id changed (PROFILE echo).

## 6. Limits (canonical table)

| Limit | Value |
|---|---|
| frame payload | 1 MiB |
| text body | 4096 bytes |
| display name | 32 bytes |
| avatar payload | 16000 bytes (one wire frame); receive rate ≤ 1 per 5 min |
| file size | 64 MB |
| file chunk | 16000 bytes |
| concurrent file transfers per peer | 8 |
| history limit parameter | 200 (0 → default 50) |
| outbox | 1000 records, TTL 30 days |
| live invites | 4 (daemon memory, not persisted) |
| message dedup window | 64 msg_ids per contact |
| presence | PING after 4 s idle; 5 s interval; 3 misses → offline |
| direct TCP port range | 7777–7786 (first free wins; all busy → LAN discovery off) |
| LAN discovery | UDP multicast 239.77.77.77:57770, 74-byte announcements |
| daemons per `$HOME` | 1 (single UDS path) |

## 7. Delivery model

1. `SEND_MESSAGE` to an offline peer → response `queued=1`. The GUI shows
   "will send later".
2. The peer appears (LAN/autodial) → the core flushes the queue itself.
3. The receiver of every TEXT sends an ACK envelope → the sender gets
   `MESSAGE_DELIVERED`: the GUI shows the "delivered" check.
4. Duplicates are impossible: msg_ids are deduplicated on receipt.
5. The queue survives a daemon restart (encrypted log); limits: 1000
   records, TTL 30 days.

Presence: online = live connection; silence > 4 s → PING/PONG; 3 misses →
offline (`PRESENCE` with online=0).

## 8. Client lifecycle

Bootstrap (analog of a gateway READY):

```
connect to $HOME/.shopot/api.sock
GET_VERSION                       — readiness probe, check major
LIST_CONTACTS                     — full contact snapshot
for each cid: GET_HISTORY(cid,50) — initial history
render; from here on, state arrives via events only
```

After bootstrap the client is purely event-driven: presence, messages,
reactions, calls, avatars, files all arrive as events. Do not poll.

## 9. Scenarios (in API terms)

### Adding a friend (same Wi-Fi)
```
A: CREATE_INVITE{name:"mom"}             → code
   (relay the code through any messenger)
B: ACCEPT_INVITE{code, my_name:"mom"}    → cid
   then: the session comes up by itself, PRESENCE online, text flows
A: listens for CONTACT_JOINED
```

### Remote (behind NAT, address known)
A: `CREATE_INVITE{name, addr:"host:7777"}` → B: `ACCEPT_INVITE`.
IP hiding: A runs `shopot relay host:port` anywhere and issues
`CREATE_INVITE` with relay=1.

### Offline conversation
A writes to offline B → `queued=1` → B starts the daemon → the core delivers
→ A: `MESSAGE_DELIVERED`.

## 10. Guarantees and boundaries

- Cryptography: XX-like handshake, AEAD transport, double ratchet — see
  PROTOCOL.md. The client never touches keys: the seed lives at
  `~/.shopot/zig-seed` (0600).
- Concurrent clients: commands execute sequentially; events are broadcast to
  all.
- Permissions: `~/.shopot` — 0700, `api.sock` — 0700, `zig-seed` — 0600.
  Everything is local to one OS user.
- Call jitter buffer: frames play from a queue at an even pace (~40–60 ms
  latency); losses are concealed by skipping seq.
- The wire is disguised as TLS 1.3 (fake-TLS). The peer sees your IP (P2P);
  hiding it requires a relay.
- Socket and files belong to `$HOME`; running several daemons on one `$HOME`
  is unsupported (single UDS path).

## 11. Versioning policy

- `GET_VERSION` returns `[major, minor, patch]`.
- **Major** — incompatible wire changes of this contract; a client must
  check it and refuse to work against a different major.
- **Minor** — compatible additions (new methods, events, payload fields at
  the end of a struct).
- Every change to this contract lands in [CHANGELOG.md](../CHANGELOG.md)
  before the release.

## Appendix A. Envelope quick reference

Full byte layouts — PROTOCOL.md §7. The client never constructs envelopes;
the core does. Useful for reading logs and events:

TEXT (0x10) carries msg_id/ts/body; ACK (0x15) — delivery confirmation;
REACT (0x13) — op + codepoint; JOIN (0x40) — invite proof; PROFILE (0x42) —
name + avatar_id; AVATAR/AVATAR_ACK/AVATAR_REQ (0x50/0x51/0x52) — avatars;
FILE_META/FILE_DATA/FILE_ACK (0x60/0x61/0x62) — files;
CALL_SIGNAL/CALL_AUDIO (0x30/0x31) — calls; PING/PONG (0x20/0x21) — presence;
BLOCK_NOTICE (0x14) — blocking.
