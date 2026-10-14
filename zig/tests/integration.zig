//! Full-stack integration: two sessions over an in-memory pipe pair —
//! handshake, obfuscated stream, ratchet-sealed TEXT, reactions, presence.
//! No network, no real time.
const std = @import("std");
const shopot = @import("shopot");
const interfaces = shopot.interfaces;
const handshake = shopot.crypto.handshake;
const identity = shopot.crypto.identity;
const envelope = shopot.proto.envelope;
const session_mod = shopot.core.session;
const obfuscate = shopot.net.obfuscate;

// -------------------------------------------------------------- pipe pair
const io_g = struct {
    var stored: std.Io = undefined;
    var alloc: std.mem.Allocator = undefined;
};

const Entry = struct {
    data: []u8,
    off: usize = 0,
};

const Pipe = struct {
    mu: std.Io.Mutex = .init,
    cv: std.Io.Condition = .init,
    inbox: std.ArrayListUnmanaged(Entry) = .empty,
    closed: bool = false,

    fn push(self: *Pipe, data: []const u8, alloc: std.mem.Allocator) void {
        self.mu.lockUncancelable(io_g.stored);
        defer self.mu.unlock(io_g.stored);
        if (self.closed) return;
        const copy = alloc.dupe(u8, data) catch return;
        self.inbox.append(alloc, .{ .data = copy }) catch {
            alloc.free(copy);
            return;
        };
        self.cv.signal(io_g.stored);
    }

    fn close(self: *Pipe) void {
        self.mu.lockUncancelable(io_g.stored);
        self.closed = true;
        self.mu.unlock(io_g.stored);
        self.cv.broadcast(io_g.stored);
    }
};

const PipeConn = struct {
    me: *Pipe,
    peer_pipe: *Pipe,
    alloc: std.mem.Allocator,

    fn readAllImpl(ptr: *anyopaque, buf: []u8) interfaces.ConnError!void {
        const self: *PipeConn = @ptrCast(@alignCast(ptr));
        var done: usize = 0;
        while (done < buf.len) {
            self.me.mu.lockUncancelable(io_g.stored);
            while (self.me.inbox.items.len == 0 and !self.me.closed)
                self.me.cv.waitUncancelable(io_g.stored, &self.me.mu);
            if (self.me.inbox.items.len == 0) {
                self.me.mu.unlock(io_g.stored);
                return interfaces.ConnError.Closed;
            }
            const ent = &self.me.inbox.items[0];
            const avail = ent.data.len - ent.off;
            const take = @min(buf.len - done, avail);
            @memcpy(buf[done .. done + take], ent.data[ent.off .. ent.off + take]);
            ent.off += take;
            if (ent.off == ent.data.len) {
                const popped = self.me.inbox.orderedRemove(0);
                io_g.alloc.free(popped.data);
            }
            self.me.mu.unlock(io_g.stored);
            done += take;
        }
    }

    fn writeAllImpl(ptr: *anyopaque, buf: []const u8) interfaces.ConnError!void {
        const self: *PipeConn = @ptrCast(@alignCast(ptr));
        self.peer_pipe.push(buf, self.alloc);
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *PipeConn = @ptrCast(@alignCast(ptr));
        self.me.close();
    }

    fn conn(self: *PipeConn) interfaces.Conn {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = interfaces.Conn.VTable{
        .readAll = readAllImpl,
        .writeAll = writeAllImpl,
        .close = closeImpl,
    };
};

fn pipePair(alloc: std.mem.Allocator) ![2]PipeConn {
    const pa = try alloc.create(Pipe);
    const pb = try alloc.create(Pipe);
    pa.* = .{};
    pb.* = .{};
    const ca = PipeConn{ .me = pa, .peer_pipe = pb, .alloc = alloc };
    const cb = PipeConn{ .me = pb, .peer_pipe = pa, .alloc = alloc };
    return .{ ca, cb };
}

// -------------------------------------------------------------- harness
const Harness = struct {
    alloc: std.mem.Allocator,
    texts: std.ArrayListUnmanaged([]u8) = .empty,
    text_ts: std.ArrayListUnmanaged(u64) = .empty,
    reacts: std.ArrayListUnmanaged(envelope.React) = .empty,
    pings: std.ArrayListUnmanaged(u32) = .empty,
    delivered: std.ArrayListUnmanaged([16]u8) = .empty,

    fn onEnvelope(ctx: *anyopaque, env: envelope.Envelope) void {
        const self: *Harness = @ptrCast(@alignCast(ctx));
        switch (env) {
            .text => |t| {
                const copy = self.alloc.dupe(u8, t.body) catch return;
                self.texts.append(self.alloc, copy) catch {};
                self.text_ts.append(self.alloc, t.ts_ms) catch {};
            },
            .react => |r| self.reacts.append(self.alloc, r) catch {},
            .presence_ping => |p| self.pings.append(self.alloc, p.seq) catch {},
            else => {},
        }
    }

    fn onClosed(_: *anyopaque) void {}
};

fn wrapConn(_: *anyopaque, raw: interfaces.Conn, keys: handshake.SessionKeys, alloc: std.mem.Allocator) anyerror!interfaces.Conn {
    var key: [32]u8 = undefined;
    shopot.crypto.kdf.expand(keys.transcript, "shopot-obf-v3", &key);
    const oc = try alloc.create(obfuscate.ObfConn);
    oc.* = try obfuscate.ObfConn.init(alloc, std.testing.io, raw, &key);
    if (obf_idx < 2) {
        obf_tracker[obf_idx] = oc;
        obf_idx += 1;
    }
    return obfuscate.obfConn(oc);
}

test "two sessions: handshake, sealed text, reaction, presence" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    io_g.stored = io;
    io_g.alloc = alloc;
    const id_a = try identity.Identity.fromSeed(filled(7));
    const id_b = try identity.Identity.fromSeed(filled(9));

    const pair = try pipePair(alloc);
    var ca = pair[0];
    var cb = pair[1];

    var ha = Harness{ .alloc = alloc };
    var hb = Harness{ .alloc = alloc };

    var sb_opt: ?*session_mod.Session = null;
    const th_b = try std.Thread.spawn(.{}, establishB, .{ alloc, cb.conn(), &id_b, id_a.bundle()[32..64].*, &hb, &sb_opt });

    const sa = try session_mod.Session.establish(
        alloc,
        ca.conn(),
        .initiator,
        &id_a,
        id_b.bundle()[32..64].*,
        filled(1),
        @ptrCast(&wrap_slot),
        wrapConn,
        .{ .ctx = &ha, .onEnvelope = Harness.onEnvelope, .onClosed = Harness.onClosed },
        io,
    );
    th_b.join();
    const sb = sb_opt orelse return error.ResponderFailed;

    try sa.sendText("privet, b!");
    try sb.sendText("privet, a!");
    try waitTexts(&ha, "privet, a!"); // A receives what B sent
    try waitTexts(&hb, "privet, b!"); // B receives what A sent

    // millisecond precision: two sends land on distinct ms ticks or at
    // least carry well-formed non-zero ms timestamps from both sides
    for ([_]*Harness{ &ha, &hb }) |h| {
        for (h.text_ts.items) |ts| try std.testing.expect(ts > 1_000_000_000);
    }

    const msg_id: [16]u8 = @splat(3);
    try sa.sendEnvelope(.{ .react = .{ .msg_id = msg_id, .op = envelope.react_add, .code = 4 } });
    try waitReact(&hb);

    try sa.sendEnvelope(.{ .presence_ping = .{ .seq = 42, .ts_ms = 1234567 } });
    try waitPing(&hb, 42);

    sa.close();
    sb.close();
    for (obf_tracker) |oc| {
        if (oc) |o| {
            o.deinit();
            alloc.destroy(o);
        }
    }
    alloc.destroy(sa);
    alloc.destroy(sb);
    ca.me.inbox.deinit(alloc);
    cb.me.inbox.deinit(alloc);
    alloc.destroy(ca.me);
    alloc.destroy(cb.me);
    for (ha.texts.items) |t| alloc.free(t);
    for (hb.texts.items) |t| alloc.free(t);
    ha.texts.deinit(alloc);
    ha.text_ts.deinit(alloc);
    hb.texts.deinit(alloc);
    hb.text_ts.deinit(alloc);
    ha.reacts.deinit(alloc);
    hb.reacts.deinit(alloc);
    ha.pings.deinit(alloc);
    hb.pings.deinit(alloc);
}

var wrap_slot: u8 = 0;
var obf_tracker: [2]?*obfuscate.ObfConn = .{ null, null };
var obf_idx: usize = 0;

fn establishB(
    alloc: std.mem.Allocator,
    conn: interfaces.Conn,
    id_b: *const identity.Identity,
    peer_sign: [32]u8,
    hb: *Harness,
    out: *?*session_mod.Session,
) void {
    out.* = session_mod.Session.establish(
        alloc,
        conn,
        .responder,
        id_b,
        peer_sign,
        filled(2),
        @ptrCast(&wrap_slot),
        wrapConn,
        .{ .ctx = hb, .onEnvelope = Harness.onEnvelope, .onClosed = Harness.onClosed },
        io_g.stored,
    ) catch null;
}

fn filled(v: u8) [32]u8 {
    const a: [32]u8 = @splat(v);
    return a;
}

fn waitTexts(h: *Harness, want: []const u8) !void {
    for (0..100) |_| {
        for (h.texts.items) |t| {
            if (std.mem.eql(u8, t, want)) return;
        }
        std.Io.sleep(io_g.stored, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
    }
    return error.TestUnexpectedResult;
}

fn waitReact(h: *Harness) !void {
    for (0..100) |_| {
        if (h.reacts.items.len > 0) return;
        std.Io.sleep(io_g.stored, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
    }
    return error.TestUnexpectedResult;
}

fn waitPing(h: *Harness, seq: u32) !void {
    for (0..100) |_| {
        for (h.pings.items) |s| {
            if (s == seq) return;
        }
        std.Io.sleep(io_g.stored, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
    }
    return error.TestUnexpectedResult;
}

// ------------------------------------------------------ block flow (E2E)
const EngineCtx = struct {
    engine: *shopot.core.engine.Engine,
    contact_id: i64,
    harness: *Harness,
};

const eng_events = struct {
    fn onText(ctx: *anyopaque, _: *const shopot.core.engine.Contact, _: [16]u8, _: i64, body: []const u8) void {
        const h: *Harness = @ptrCast(@alignCast(ctx));
        const copy = h.alloc.dupe(u8, body) catch return;
        h.texts.append(h.alloc, copy) catch {};
    }
    fn onReaction(ctx: *anyopaque, _: *const shopot.core.engine.Contact, r: shopot.core.engine.Reaction) void {
        const h: *Harness = @ptrCast(@alignCast(ctx));
        h.reacts.append(h.alloc, .{ .msg_id = r.msg_id, .op = envelope.react_add, .code = r.code }) catch {};
    }
    fn onDelivered(ctx: *anyopaque, _: *const shopot.core.engine.Contact, msg_id: [16]u8) void {
        const h: *Harness = @ptrCast(@alignCast(ctx));
        h.delivered.append(h.alloc, msg_id) catch {};
    }
};

fn engineDispatch(ctx: *anyopaque, env: envelope.Envelope) void {
    const self: *EngineCtx = @ptrCast(@alignCast(ctx));
    self.engine.dispatch(self.contact_id, env);
}

test "block: traffic from blocked peer is dropped engine-wide" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    io_g.stored = io;
    io_g.alloc = alloc;

    obf_idx = 0;
    obf_tracker = .{ null, null };
    const id_a = try identity.Identity.fromSeed(filled(11));
    const id_b = try identity.Identity.fromSeed(filled(13));
    const pair = try pipePair(alloc);
    var ca = pair[0];
    var cb = pair[1];

    var ha = Harness{ .alloc = alloc };
    var hb = Harness{ .alloc = alloc };

    var eng_a = shopot.core.engine.Engine.init(alloc, io, id_a, .{
        .ctx = &ha,
        .onText = eng_events.onText,
        .onReaction = eng_events.onReaction,
    });
    var eng_b = shopot.core.engine.Engine.init(alloc, io, id_b, .{
        .ctx = &hb,
        .onText = eng_events.onText,
        .onReaction = eng_events.onReaction,
    });

    const idx_b = try eng_a.addContact("b", id_b.bundle());
    _ = try eng_b.addContact("a", id_a.bundle());
    const cid_b: i64 = @intCast(idx_b + 1);

    var ctx_a = EngineCtx{ .engine = &eng_a, .contact_id = cid_b, .harness = &ha };
    var ctx_b = EngineCtx{ .engine = &eng_b, .contact_id = 1, .harness = &hb };

    // establish as in test 1 (responder on its own thread)
    var sb_opt: ?*session_mod.Session = null;
    const th_b = try std.Thread.spawn(.{}, struct {
        fn go(conn: interfaces.Conn, id_b_ptr: *const identity.Identity, peer_sign: [32]u8, ctx: *EngineCtx, out: *?*session_mod.Session) void {
            out.* = session_mod.Session.establish(
                io_g.alloc,
                conn,
                .responder,
                id_b_ptr,
                peer_sign,
                filled(5),
                @ptrCast(&wrap_slot),
                wrapConn,
                .{ .ctx = ctx, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
                io_g.stored,
            ) catch null;
        }
    }.go, .{ cb.conn(), &id_b, id_a.bundle()[32..64].*, &ctx_b, &sb_opt });

    const sa = try session_mod.Session.establish(
        alloc,
        ca.conn(),
        .initiator,
        &id_a,
        id_b.bundle()[32..64].*,
        filled(4),
        @ptrCast(&wrap_slot),
        wrapConn,
        .{ .ctx = &ctx_a, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
        io,
    );
    th_b.join();
    const sb = sb_opt orelse return error.ResponderFailed;

    eng_a.sessions.put(cid_b, sa) catch return error.OutOfMemory;
    eng_b.sessions.put(1, sb) catch return error.OutOfMemory;

    // before block: text goes through the full engine dispatch
    _ = try eng_b.sendText(1, "hello a");
    try waitTexts(&ha, "hello a");

    // A blocks B: engine marks flag, warns peer, tears the session down
    try eng_a.block(cid_b);
    try std.testing.expect(eng_a.contacts.items[idx_b].blocked);
    try std.testing.expectError(shopot.core.engine.EngineError.Blocked, eng_a.sendText(cid_b, "nope"));

    // B (unaware yet or ignoring) keeps sending: everything is dropped at A
    _ = try eng_b.sendText(1, "should vanish");
    try eng_b.react(1, @splat(9), envelope.react_add, 5);
    std.Thread.yield() catch {};
    std.Io.sleep(io_g.stored, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake) catch {};
    try std.testing.expectEqual(@as(usize, 1), ha.texts.items.len); // only "hello a"
    try std.testing.expectEqual(@as(usize, 0), ha.reacts.items.len);

    // A cannot unblock into the void: unblock is local and needs re-handshake
    try eng_a.unblock(cid_b);
    try std.testing.expect(!eng_a.contacts.items[idx_b].blocked);

    sb.close();
    std.debug.print("TEARDOWN a_sessions={d} b_sessions={d}\n", .{ eng_a.sessions.count(), eng_b.sessions.count() });
    _ = eng_a.sessions.remove(cid_b);
    _ = eng_b.sessions.remove(1);
    eng_a.deinit();
    eng_b.deinit();
    for (obf_tracker) |oc| {
        if (oc) |o| {
            o.deinit();
            alloc.destroy(o);
        }
    }
    alloc.destroy(sa);
    alloc.destroy(sb);
    ca.me.inbox.deinit(alloc);
    cb.me.inbox.deinit(alloc);
    alloc.destroy(ca.me);
    alloc.destroy(cb.me);
    for (ha.texts.items) |tx| alloc.free(tx);
    for (hb.texts.items) |tx| alloc.free(tx);
    ha.texts.deinit(alloc);
    ha.text_ts.deinit(alloc);
    hb.texts.deinit(alloc);
    hb.text_ts.deinit(alloc);
    ha.reacts.deinit(alloc);
    hb.reacts.deinit(alloc);
    ha.pings.deinit(alloc);
    hb.pings.deinit(alloc);
}

// ------------------------------------------------------ outbox flow (E2E)
test "outbox: очередь офлайн, доставка при сессии, ACK, дедуп" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    io_g.stored = io;
    io_g.alloc = alloc;

    obf_idx = 0;
    obf_tracker = .{ null, null };
    const id_a = try identity.Identity.fromSeed(filled(21));
    const id_b = try identity.Identity.fromSeed(filled(23));
    const pair = try pipePair(alloc);
    var ca = pair[0];
    var cb = pair[1];

    var ha = Harness{ .alloc = alloc };
    var hb = Harness{ .alloc = alloc };

    var eng_a = shopot.core.engine.Engine.init(alloc, io, id_a, .{
        .ctx = &ha,
        .onText = eng_events.onText,
        .onDelivered = eng_events.onDelivered,
    });
    var eng_b = shopot.core.engine.Engine.init(alloc, io, id_b, .{
        .ctx = &hb,
        .onText = eng_events.onText,
        .onDelivered = eng_events.onDelivered,
    });

    const idx_b = try eng_a.addContact("b", id_b.bundle());
    _ = try eng_b.addContact("a", id_a.bundle());
    const cid_b: i64 = @intCast(idx_b + 1);

    var ctx_a = EngineCtx{ .engine = &eng_a, .contact_id = cid_b, .harness = &ha };
    var ctx_b = EngineCtx{ .engine = &eng_b, .contact_id = 1, .harness = &hb };

    // 1) офлайн: TEXT уходит в очередь, не в ошибку
    try std.testing.expectEqual(shopot.core.engine.Engine.SendResult.queued, try eng_b.sendText(1, "offline-digest"));
    try std.testing.expectEqual(@as(usize, 1), eng_b.outbox.items.len);

    // 2) поднимаем сессии
    var sb_opt: ?*session_mod.Session = null;
    const th_b = try std.Thread.spawn(.{}, struct {
        fn go(conn: interfaces.Conn, id_b_ptr: *const identity.Identity, peer_sign: [32]u8, ctx: *EngineCtx, out: *?*session_mod.Session) void {
            out.* = session_mod.Session.establish(
                io_g.alloc,
                conn,
                .responder,
                id_b_ptr,
                peer_sign,
                filled(6),
                @ptrCast(&wrap_slot),
                wrapConn,
                .{ .ctx = ctx, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
                io_g.stored,
            ) catch null;
        }
    }.go, .{ cb.conn(), &id_b, id_a.bundle()[32..64].*, &ctx_b, &sb_opt });

    const sa = try session_mod.Session.establish(
        alloc,
        ca.conn(),
        .initiator,
        &id_a,
        id_b.bundle()[32..64].*,
        filled(4),
        @ptrCast(&wrap_slot),
        wrapConn,
        .{ .ctx = &ctx_a, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
        io,
    );
    th_b.join();
    const sb = sb_opt orelse return error.ResponderFailed;

    eng_a.sessions.put(cid_b, sa) catch return error.OutOfMemory;
    eng_b.sessions.put(1, sb) catch return error.OutOfMemory;

    // 3) сессия поднялась — слить очередь
    eng_b.flushOutbox(1);
    try waitTexts(&ha, "offline-digest");

    // 4) ACK от A погасил запись outbox у B (доставлено)
    for (0..200) |_| {
        if (eng_b.outbox.items.len == 0) break;
        std.Io.sleep(io_g.stored, .{ .nanoseconds = 5 * std.time.ns_per_ms }, .awake) catch {};
    }
    try std.testing.expectEqual(@as(usize, 0), eng_b.outbox.items.len);
    try std.testing.expectEqual(@as(usize, 1), hb.delivered.items.len);

    // 5) дедуп: один и тот же TEXT дважды — получен один раз (B -> A)
    const dup_mid: [16]u8 = @splat(0xD1);
    const dup = envelope.Envelope{ .text = .{ .msg_id = dup_mid, .ts_ms = 77, .body = "dup" } };
    try sb.sendEnvelope(dup);
    try waitTexts(&ha, "dup");
    try sb.sendEnvelope(dup);
    std.Thread.yield() catch {};
    std.Io.sleep(io_g.stored, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .awake) catch {};
    var n: usize = 0;
    for (ha.texts.items) |t| {
        if (std.mem.eql(u8, t, "dup")) n += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), n);

    sb.close();
    _ = eng_a.sessions.remove(cid_b);
    sa.close();
    _ = eng_b.sessions.remove(1);
    eng_a.deinit();
    eng_b.deinit();
    for (obf_tracker) |oc| {
        if (oc) |o| {
            o.deinit();
            alloc.destroy(o);
        }
    }
    alloc.destroy(sa);
    alloc.destroy(sb);
    ca.me.inbox.deinit(alloc);
    cb.me.inbox.deinit(alloc);
    alloc.destroy(ca.me);
    alloc.destroy(cb.me);
    for (ha.texts.items) |tx| alloc.free(tx);
    for (hb.texts.items) |tx| alloc.free(tx);
    ha.texts.deinit(alloc);
    ha.text_ts.deinit(alloc);
    hb.texts.deinit(alloc);
    hb.text_ts.deinit(alloc);
    hb.delivered.deinit(alloc);
}
