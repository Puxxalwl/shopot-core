//! One encrypted session with one contact over one transport connection.
//! Flow: transport connect -> XX handshake (both identities authenticated by
//! Ed25519 signatures over the transcript) -> traffic keys -> caller-provided
//! stream wrapper (obfuscated AEAD) -> framed envelopes. TEXT payloads are
//! additionally sealed by the per-message ratchet: two independent crypto
//! layers, each with its own forward secrecy.
const std = @import("std");
const interfaces = @import("interfaces.zig");
const handshake = @import("../crypto/handshake.zig");
const ratchet_mod = @import("../crypto/ratchet.zig");
const kdf = @import("../crypto/kdf.zig");
const aead = @import("../crypto/aead.zig");
const identity_mod = @import("../crypto/identity.zig");
const envelope = @import("../proto/envelope.zig");

pub const SessionError = error{
    HandshakeFailed,
    BadSignature,
    Tampered,
    Closed,
    OutOfSpace,
    TooBig,
};

pub const HandshakeRole = enum { initiator, responder };

/// The engine wraps the raw transport into the encrypted stream once the
/// handshake yields the traffic keys. Keeps session.zig free of net/ imports.
pub const WrapFn = *const fn (
    ctx: *anyopaque,
    raw: interfaces.Conn,
    keys: handshake.SessionKeys,
    alloc: std.mem.Allocator,
) anyerror!interfaces.Conn;

pub const Events = struct {
    ctx: *anyopaque,
    onEnvelope: *const fn (ctx: *anyopaque, env: envelope.Envelope) void,
    onClosed: *const fn (ctx: *anyopaque) void,
};

const sealed_tag: u8 = 0xA1; // ratchet-sealed TEXT frame marker

pub const Session = struct {
    conn: interfaces.Conn,
    ratchet: ratchet_mod.Ratchet,
    ev: Events,
    send_mu: std.Io.Mutex = .init,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    rx_thread: ?std.Thread = null,
    alloc: std.mem.Allocator,
    io: std.Io,

    pub fn establish(
        alloc: std.mem.Allocator,
        conn: interfaces.Conn,
        role: HandshakeRole,
        my_id: *const identity_mod.Identity,
        peer_sign_pk: [32]u8,
        eph_seed: [32]u8,
        wrap_ctx: *anyopaque,
        wrap: WrapFn,
        ev: Events,
        io: std.Io,
    ) SessionError!*Session {
        var keys: handshake.SessionKeys = undefined;
        switch (role) {
            .initiator => {
                var m1: [handshake.m1_len]u8 = undefined;
                var m2: [handshake.m2_len]u8 = undefined;
                var m3: [handshake.m3_len]u8 = undefined;
                var hs = handshake.Initiator.start(&m1, my_id, eph_seed);
                writeFrame(conn, &m1) catch return SessionError.Closed;
                _ = readFrame(conn, &m2) catch return SessionError.Closed;
                keys = hs.recv2(&m3, &m2, peer_sign_pk) catch |e| switch (e) {
                    error.BadSignature => return SessionError.BadSignature,
                    else => return SessionError.HandshakeFailed,
                };
                writeFrame(conn, &m3) catch return SessionError.Closed;
            },
            .responder => {
                var m1: [handshake.m1_len]u8 = undefined;
                var m2: [handshake.m2_len]u8 = undefined;
                var m3: [handshake.m3_len]u8 = undefined;
                _ = readFrame(conn, &m1) catch return SessionError.Closed;
                var hs = handshake.Responder.recv1(&m2, my_id, &m1, eph_seed) catch
                    return SessionError.HandshakeFailed;
                writeFrame(conn, &m2) catch return SessionError.Closed;
                _ = readFrame(conn, &m3) catch return SessionError.Closed;
                keys = hs.recv3(&m3, peer_sign_pk) catch |e| switch (e) {
                    error.BadSignature => return SessionError.BadSignature,
                    else => return SessionError.HandshakeFailed,
                };
            },
        }

        const wrapped = wrap(wrap_ctx, conn, keys, alloc) catch return SessionError.OutOfSpace;

        // Ratchet chains: label 1 is A->B, label 2 is B->A. The initiator maps
        // send->1/recv->2, the responder the mirror, so the send chain of one
        // side is byte-identical to the recv chain of the other.
        var chain_send: [32]u8 = undefined;
        var chain_recv: [32]u8 = undefined;
        switch (role) {
            .initiator => {
                kdf.expand(keys.transcript, "shopot-chain-1", &chain_send);
                kdf.expand(keys.transcript, "shopot-chain-2", &chain_recv);
            },
            .responder => {
                kdf.expand(keys.transcript, "shopot-chain-2", &chain_send);
                kdf.expand(keys.transcript, "shopot-chain-1", &chain_recv);
            },
        }

        const self = alloc.create(Session) catch return SessionError.OutOfSpace;
        errdefer alloc.destroy(self);
        self.* = .{
            .conn = wrapped,
            .ratchet = ratchet_mod.Ratchet.init(chain_send, chain_recv),
            .ev = ev,
            .alloc = alloc,
            .io = io,
        };
        self.rx_thread = std.Thread.spawn(.{}, rxLoop, .{self}) catch {
            wrapped.close();
            alloc.destroy(self);
            return SessionError.OutOfSpace;
        };
        return self;
    }

    /// TEXT: ratchet-sealed (layer 2) before the obfuscated stream (layer 1).
    pub fn sendText(self: *Session, body: []const u8) SessionError!void {
        if (body.len > envelope.max_text_body) return SessionError.TooBig;
        var env_buf: [envelope.max_encoded_len]u8 = undefined;
        var msg_id: [16]u8 = undefined;
        self.fillRandom(&msg_id);
        var ts_buf: [8]u8 = undefined;
        self.io.random(&ts_buf);
        const ts_ms: u64 = std.mem.readInt(u64, &ts_buf, .little) % 100_000_000_000_000;
        const plain = envelope.encode(&env_buf, .{ .text = .{
            .msg_id = msg_id,
            .ts_ms = ts_ms,
            .body = body,
        } }) catch return SessionError.TooBig;

        var msg_key: [32]u8 = undefined;
        var out: [envelope.max_encoded_len + 64]u8 = undefined;
        self.send_mu.lockUncancelable(self.io);
        defer self.send_mu.unlock(self.io);
        const counter = self.ratchet.stepSend(&msg_key);
        out[0] = sealed_tag;
        std.mem.writeInt(u64, out[1..9], counter, .little);
        const nonce = aead.nonceFor(counter);
        aead.seal(out[9..], plain, msg_key, nonce, out[0..9]);
        writeFrame(self.conn, out[0 .. 9 + plain.len + aead.tag_length]) catch return SessionError.Closed;
    }

    /// Everything else rides the transport layer only (presence, reactions,
    /// call signaling and audio have their own per-call keys).
    pub fn sendEnvelope(self: *Session, env: envelope.Envelope) SessionError!void {
        var buf: [envelope.max_encoded_len]u8 = undefined;
        const plain = envelope.encode(&buf, env) catch return SessionError.TooBig;
        self.send_mu.lockUncancelable(self.io);
        defer self.send_mu.unlock(self.io);
        writeFrame(self.conn, plain) catch return SessionError.Closed;
    }

    pub fn close(self: *Session) void {
        if (self.running.swap(false, .seq_cst)) {
            self.conn.close();
            if (self.rx_thread) |t| t.join();
            self.rx_thread = null;
            self.ev.onClosed(self.ev.ctx);
        }
    }

    fn rxLoop(self: *Session) void {
        var buf: [envelope.max_encoded_len + 64]u8 = undefined;
        while (self.running.load(.seq_cst)) {
            const n = readFrame(self.conn, &buf) catch break;
            if (n == 0) break;
            var env: envelope.Envelope = undefined;
            if (buf[0] == sealed_tag) {
                if (n < 10) continue;
                const counter = std.mem.readInt(u64, buf[1..9], .little);
                var msg_key: [32]u8 = undefined;
                self.send_mu.lockUncancelable(self.io);
                const got = self.ratchet.stepRecv(&msg_key);
                self.send_mu.unlock(self.io);
                _ = got;
                const nonce = aead.nonceFor(counter);
                const box = buf[9..n];
                var plain_buf: [envelope.max_encoded_len]u8 = undefined;
                aead.open(&plain_buf, box, msg_key, nonce, buf[0..9]) catch continue;
                const plain_len = box.len - aead.tag_length;
                env = envelope.decode(plain_buf[0..plain_len]) catch continue;
            } else {
                env = envelope.decode(buf[0..n]) catch continue;
            }
            self.ev.onEnvelope(self.ev.ctx, env);
        }
        self.running.store(false, .seq_cst);
        self.ev.onClosed(self.ev.ctx);
    }

    fn fillRandom(self: *Session, dest: []u8) void {
        // counters and nonces come from AEAD/ratchet; only msg_id needs entropy
        self.io.random(dest);
    }
};

fn writeFrame(conn: interfaces.Conn, payload: []const u8) !void {
    if (payload.len > 65535) return error.FrameTooBig;
    var hdr: [2]u8 = undefined;
    std.mem.writeInt(u16, &hdr, @intCast(payload.len), .little);
    try conn.writeAll(&hdr);
    try conn.writeAll(payload);
}

fn readFrame(conn: interfaces.Conn, buf: []u8) !usize {
    var hdr: [2]u8 = undefined;
    try conn.readAll(&hdr);
    const len = std.mem.readInt(u16, &hdr, .little);
    if (len > buf.len) return error.FrameTooBig;
    try conn.readAll(buf[0..len]);
    return len;
}

test "session module compiles" {
    _ = Session;
    _ = SessionError;
}
