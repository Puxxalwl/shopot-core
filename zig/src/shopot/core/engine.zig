//! Engine: owns identity, contacts, blocklist, sessions, call and presence
//! state. All storage goes through the sealed log; nothing is ever plaintext
//! on disk. Callbacks fire from session threads — keep them fast or queue.
const std = @import("std");
const interfaces = @import("interfaces.zig");
const identity_mod = @import("../crypto/identity.zig");
const envelope = @import("../proto/envelope.zig");
const session_mod = @import("session.zig");

pub const EngineError = error{
    Blocked,
    NoSession,
    NoSpace,
    Store,
};

pub const Contact = struct {
    name: [32]u8 = @splat(0),
    name_len: u8 = 0,
    bundle: [64]u8 = @splat(0), // enc_pk || sign_pk
    online: bool = false,
    blocked: bool = false,

    pub fn setName(self: *Contact, name: []const u8) void {
        const n = @min(name.len, self.name.len);
        @memcpy(self.name[0..n], name[0..n]);
        self.name_len = @intCast(n);
    }
    pub fn getName(self: *const Contact) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const Reaction = struct {
    msg_id: [16]u8,
    from: [64]u8, // peer bundle
    code: u8,
};

pub const Events = struct {
    ctx: *anyopaque = undefined,
    onText: ?*const fn (ctx: *anyopaque, from: *const Contact, msg_id: [16]u8, ts_ms: i64, body: []const u8) void = null,
    onReaction: ?*const fn (ctx: *anyopaque, from: *const Contact, r: Reaction) void = null,
    onPresence: ?*const fn (ctx: *anyopaque, from: *const Contact, online: bool, last_seen_ms: i64) void = null,
    onCallSignal: ?*const fn (ctx: *anyopaque, from: *const Contact, op: u8, call_id: [16]u8) void = null,
    onCallAudio: ?*const fn (ctx: *anyopaque, from: *const Contact, seq: u32, data: []const u8) void = null,
    onBlockedNotice: ?*const fn (ctx: *anyopaque, from: *const Contact) void = null,
};

pub const Engine = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    id: identity_mod.Identity,
    ev: Events,

    contacts: std.ArrayListUnmanaged(Contact) = .empty,
    contact_ids: std.ArrayListUnmanaged(i64) = .empty, // stable small ids

    sessions: std.AutoHashMap(i64, *session_mod.Session),

    // presence: millisecond precision, passive
    last_seen_ms: std.AutoHashMap(i64, i64),

    pub fn init(alloc: std.mem.Allocator, io: std.Io, id: identity_mod.Identity, ev: Events) Engine {
        return .{
            .alloc = alloc,
            .io = io,
            .id = id,
            .ev = ev,
            .sessions = std.AutoHashMap(i64, *session_mod.Session).init(alloc),
            .last_seen_ms = std.AutoHashMap(i64, i64).init(alloc),
        };
    }

    pub fn deinit(self: *Engine) void {
        var it = self.sessions.valueIterator();
        while (it.next()) |s| {
            s.*.close();
        }
        self.sessions.deinit();
        self.contacts.deinit(self.alloc);
        self.contact_ids.deinit(self.alloc);
        self.last_seen_ms.deinit();
    }

    pub fn addContact(self: *Engine, name: []const u8, bundle: [64]u8) !usize {
        var c = Contact{};
        c.setName(name);
        c.bundle = bundle;
        try self.contacts.append(self.alloc, c);
        const idx = self.contacts.items.len - 1;
        try self.contact_ids.append(self.alloc, @intCast(idx + 1));
        return idx;
    }

    fn findIndex(self: *Engine, id: i64) ?usize {
        if (id < 1) return null;
        const idx: usize = @intCast(id - 1);
        if (idx >= self.contacts.items.len) return null;
        return idx;
    }

    /// Send text to a contact. Blocked peers are rejected locally.
    pub fn sendText(self: *Engine, contact_id: i64, body: []const u8) EngineError!void {
        const idx = self.findIndex(contact_id) orelse return EngineError.NoSession;
        if (self.contacts.items[idx].blocked) return EngineError.Blocked;
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        var msg_id: [16]u8 = undefined;
        self.io.random(&msg_id);
        var ts_buf: [8]u8 = undefined;
        self.io.random(&ts_buf);
        const ts_ms: u64 = std.mem.readInt(u64, &ts_buf, .little) % 100_000_000_000_000;
        const env = envelope.Envelope{ .text = .{
            .msg_id = msg_id,
            .ts_ms = ts_ms,
            .body = body,
        } };
        s.sendEnvelope(env) catch return EngineError.NoSession;
    }

    pub fn react(self: *Engine, contact_id: i64, msg_id: [16]u8, op: u8, code: u8) EngineError!void {
        const idx = self.findIndex(contact_id) orelse return EngineError.NoSession;
        if (self.contacts.items[idx].blocked) return EngineError.Blocked;
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .react = .{ .msg_id = msg_id, .op = op, .code = code } }) catch return EngineError.NoSession;
    }

    pub fn block(self: *Engine, contact_id: i64) EngineError!void {
        const idx = self.findIndex(contact_id) orelse return EngineError.NoSession;
        self.contacts.items[idx].blocked = true;
        if (self.sessions.get(contact_id)) |s| {
            s.sendEnvelope(.{ .block_notice = .{ .reason = 0 } }) catch {};
            s.close();
            _ = self.sessions.remove(contact_id);
        }
    }

    pub fn unblock(self: *Engine, contact_id: i64) EngineError!void {
        const idx = self.findIndex(contact_id) orelse return EngineError.NoSession;
        self.contacts.items[idx].blocked = false;
    }

    pub fn callSignal(self: *Engine, contact_id: i64, op: u8, call_id: [16]u8) EngineError!void {
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .call_signal = .{ .op = op, .call_id = call_id } }) catch return EngineError.NoSession;
    }

    pub fn callAudio(self: *Engine, contact_id: i64, seq: u32, data: []const u8) EngineError!void {
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .call_audio = .{ .seq = seq, .data = data } }) catch return EngineError.NoSession;
    }

    /// Millisecond wall time through the injected io.
    pub fn nowMs(self: *Engine) i64 {
        const ts = std.Io.Clock.now(.real, self.io);
        return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
    }

    pub fn markSeen(self: *Engine, contact_id: i64, now_ms: i64) void {
        self.last_seen_ms.put(contact_id, now_ms) catch {};
        const idx = self.findIndex(contact_id) orelse return;
        const was = self.contacts.items[idx].online;
        self.contacts.items[idx].online = true;
        if (!was) {
            if (self.ev.onPresence) |cb|
                cb(self.ev.ctx, &self.contacts.items[idx], true, now_ms);
        }
    }

    pub fn lastSeen(self: *Engine, contact_id: i64) ?i64 {
        return self.last_seen_ms.get(contact_id);
    }

    /// Engine-side envelope dispatch. Runs on a session read thread.
    pub fn dispatch(self: *Engine, contact_id: i64, env: envelope.Envelope) void {
        const idx = self.findIndex(contact_id) orelse return;
        const c = &self.contacts.items[idx];
        if (c.blocked) return; // hard ignore for blocked peers
        switch (env) {
            .text => |t| {
                if (self.ev.onText) |cb| cb(self.ev.ctx, c, t.msg_id, @intCast(t.ts_ms), t.body);
            },
            .react => |r| {
                if (self.ev.onReaction) |cb| cb(self.ev.ctx, c, .{ .msg_id = r.msg_id, .from = c.bundle, .code = r.code });
            },
            .block_notice => {
                if (self.ev.onBlockedNotice) |cb| cb(self.ev.ctx, c);
            },
            .presence_ping => |p| {
                const now = self.nowMs();
                self.markSeen(contact_id, now);
                if (self.sessions.get(contact_id)) |s| {
                    s.sendEnvelope(.{ .presence_pong = .{ .seq = p.seq, .ts_peer_ms = @intCast(now) } }) catch {};
                }
            },
            .presence_pong => {
                self.markSeen(contact_id, self.nowMs());
            },
            .call_signal => |cs| {
                if (self.ev.onCallSignal) |cb| cb(self.ev.ctx, c, cs.op, cs.call_id);
            },
            .call_audio => |ca| {
                if (self.ev.onCallAudio) |cb| cb(self.ev.ctx, c, ca.seq, ca.data);
            },
            // JOIN обрабатывается слоем приложения ДО dispatch (pending-сессии);
            // сюда попадает только повторный кадр на уже промоутнутой сессии
            .join => {},
        }
    }
};

fn filled32(v: u8) [32]u8 {
    const a: [32]u8 = @splat(v);
    return a;
}

test "engine block and react flow" {
    const alloc = std.testing.allocator;
    const id = try identity_mod.Identity.fromSeed(filled32(7));
    const peer = try identity_mod.Identity.fromSeed(filled32(9));
    var eng = Engine.init(alloc, std.testing.io, id, .{ .ctx = undefined });
    defer eng.deinit();
    const idx = try eng.addContact("peer", peer.bundle());
    const cid: i64 = @intCast(idx + 1);
    try std.testing.expectError(EngineError.NoSession, eng.sendText(cid, "hi"));
    try eng.block(cid);
    try std.testing.expect(eng.contacts.items[idx].blocked);
    try eng.unblock(cid);
}
