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
const tcp = shopot.net.tcp;
const relay = shopot.net.relay;

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

/// Освободить данные, оставшиеся в очереди трубы при закрытии сессий
/// (кадры в полёте честно теряются — как в реальной сети).
fn drainPipe(p: *Pipe) void {
    p.mu.lockUncancelable(io_g.stored);
    for (p.inbox.items) |e| io_g.alloc.free(e.data);
    p.inbox.clearRetainingCapacity();
    p.mu.unlock(io_g.stored);
}

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
    /// Хвост entities i-го TEXT, принятого через движок (первые 64 байтов).
    ent_tails: [16][64]u8 = @splat(@splat(0)),
    ent_tail_lens: [16]u16 = @splat(0),
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
    if (obf_idx < obf_tracker.len) {
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
    const th_b = try std.Thread.spawn(.{}, establishB, .{ alloc, cb.conn(), &id_b, id_a.bundle(), &hb, &sb_opt });

    const sa = try session_mod.Session.establish(
        alloc,
        ca.conn(),
        .initiator,
        &id_a,
        id_b.bundle(),
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
var obf_tracker: [4]?*obfuscate.ObfConn = @splat(null);
var obf_idx: usize = 0;
/// Сериализация доступа к движкам в E2E (в проде эту роль играет app.mu:
/// envIn и API-обработчики под одним локом). rx-потоки заходят через
/// engineDispatch, главный поток — берёт лок явно. Порядок eng_mu ->
/// session.send_mu, обратного пути нет (onEnvelope вызывается вне
/// send_mu), дедлока не будет.
var eng_mu: std.Io.Mutex = .init;

fn establishB(
    alloc: std.mem.Allocator,
    conn: interfaces.Conn,
    id_b: *const identity.Identity,
    peer_bundle: [64]u8,
    hb: *Harness,
    out: *?*session_mod.Session,
) void {
    out.* = session_mod.Session.establish(
        alloc,
        conn,
        .responder,
        id_b,
        peer_bundle,
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
    fn onText(ctx: *anyopaque, _: *const shopot.core.engine.Contact, _: [16]u8, _: i64, body: []const u8, ents: []const envelope.TextEntity) void {
        const h: *Harness = @ptrCast(@alignCast(ctx));
        const copy = h.alloc.dupe(u8, body) catch return;
        h.texts.append(h.alloc, copy) catch {};
        // хвост entities движок уже распарсил; сериализуем обратно в тот же
        // канонический формат и копируем (срезы события короткоживущи)
        var tail_buf: [envelope.max_text_tail]u8 = undefined;
        const tail = envelope.encodeEntitiesTail(&tail_buf, ents, body.len) catch return;
        const i = h.texts.items.len - 1;
        if (i < h.ent_tails.len) {
            const n: usize = @min(tail.len, 64);
            @memcpy(h.ent_tails[i][0..n], tail[0..n]);
            h.ent_tail_lens[i] = @intCast(n);
        }
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
    eng_mu.lockUncancelable(io_g.stored);
    self.engine.dispatch(self.contact_id, env);
    eng_mu.unlock(io_g.stored);
}

test "block: traffic from blocked peer is dropped engine-wide" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    io_g.stored = io;
    io_g.alloc = alloc;

    obf_idx = 0;
    obf_tracker = @splat(null);
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
        fn go(conn: interfaces.Conn, id_b_ptr: *const identity.Identity, peer_bundle: [64]u8, ctx: *EngineCtx, out: *?*session_mod.Session) void {
            out.* = session_mod.Session.establish(
                io_g.alloc,
                conn,
                .responder,
                id_b_ptr,
                peer_bundle,
                filled(5),
                @ptrCast(&wrap_slot),
                wrapConn,
                .{ .ctx = ctx, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
                io_g.stored,
            ) catch null;
        }
    }.go, .{ cb.conn(), &id_b, id_a.bundle(), &ctx_b, &sb_opt });

    const sa = try session_mod.Session.establish(
        alloc,
        ca.conn(),
        .initiator,
        &id_a,
        id_b.bundle(),
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
    _ = try eng_b.sendText(1, "hello a", &.{});
    try waitTexts(&ha, "hello a");

    // A blocks B: engine marks flag, warns peer, tears the session down
    try eng_a.block(cid_b);
    try std.testing.expect(eng_a.contacts.items[idx_b].blocked);
    try std.testing.expectError(shopot.core.engine.EngineError.Blocked, eng_a.sendText(cid_b, "nope", &.{}));

    // B (unaware yet or ignoring) keeps sending: everything is dropped at A
    _ = try eng_b.sendText(1, "should vanish", &.{});
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
test "ratchet: PCS-ротация по порогу отправки, все сообщения доезжают" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    io_g.stored = io;
    io_g.alloc = alloc;
    obf_idx = 0;
    obf_tracker = @splat(null);
    const id_a = try identity.Identity.fromSeed(filled(21));
    const id_b = try identity.Identity.fromSeed(filled(23));

    const pair = try pipePair(alloc);
    var ca = pair[0];
    var cb = pair[1];

    var ha = Harness{ .alloc = alloc };
    var hb = Harness{ .alloc = alloc };

    var sb_opt: ?*session_mod.Session = null;
    const th_b = try std.Thread.spawn(.{}, establishB, .{ alloc, cb.conn(), &id_b, id_a.bundle(), &hb, &sb_opt });

    const sa = try session_mod.Session.establish(
        alloc,
        ca.conn(),
        .initiator,
        &id_a,
        id_b.bundle(),
        filled(2),
        @ptrCast(&wrap_slot),
        wrapConn,
        .{ .ctx = &ha, .onEnvelope = Harness.onEnvelope, .onClosed = Harness.onClosed },
        io,
    );
    th_b.join();
    const sb = sb_opt orelse return error.ResponderFailed;

    // порог ротации 4: за 24 сообщения обе стороны обменяются RATCHET_KEY
    // несколько раз; кадры «в полёте» между RATCHET_KEY и dhStep должны
    // расшифровываться по снапшоту цепочки, ни одно TEXT не теряется
    sa.rotate_every = 4;
    sb.rotate_every = 4;

    for (0..24) |i| {
        var body_buf: [16]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buf, "a->b {d:0>2}", .{i});
        try sa.sendText(body);
    }
    for (0..24) |i| {
        var body_buf: [16]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buf, "b->a {d:0>2}", .{i});
        try sb.sendText(body);
    }
    for (0..24) |i| {
        var body_buf: [16]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buf, "a->b {d:0>2}", .{i});
        try waitTexts(&hb, body);
    }
    for (0..24) |i| {
        var body_buf: [16]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buf, "b->a {d:0>2}", .{i});
        try waitTexts(&ha, body);
    }

    // ротация реально случилась; завершение последнего обмена асинхронно
    // (ответный паблик в полёте) — ждём синхронности эпох с таймаутом
    try std.testing.expect(sa.ratchet.epoch > 1);
    var synced = false;
    for (0..200) |_| {
        if (sa.ratchet.epoch == sb.ratchet.epoch) {
            synced = true;
            break;
        }
        std.Io.sleep(io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
    }
    try std.testing.expect(synced);
    // снапшот prev_recv гасится первым кадром новой эпохи; у получателя
    // последнего RATCHET_KEY он может остаться до следующего кадра —
    // это не ошибка, протокол держит его сколько угодно долго

    // после ротации обычный обмен жив
    try sa.sendText("post-rotate");
    try waitTexts(&hb, "post-rotate");

    // zlib-сжатие payload: длинный текст (>512) через весь стек —
    // compress -> seal -> obf -> pipe -> open -> decompress -> decode
    const long_word = "сжатиеpayload ";
    var long_buf: [3000]u8 = undefined;
    for (&long_buf, 0..) |*b, i| b.* = long_word[i % long_word.len];
    long_buf[long_buf.len - 1] = '!';
    try sa.sendText(long_buf[0..]);
    try waitTexts(&hb, long_buf[0..]);
    try sb.sendText(long_buf[0..]);
    try waitTexts(&ha, long_buf[0..]);
    // кадр новой эпохи дошёл и погасил снапшот у B
    try std.testing.expect(sb.prev_recv == null);

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

// --------------------------------------------- relay presence (E2E, TCP)

/// Сторона presence-соединения: dial в релей marker-ом из контакт-секрета,
/// рукопожатие. Роль — по порядку bundle (детерминизм на обеих сторонах).
fn relayPresenceSide(
    alloc: std.mem.Allocator,
    id: *const identity.Identity,
    peer_bundle: [64]u8,
    eph: [32]u8,
    role: session_mod.HandshakeRole,
    addr: []const u8,
    marker: [32]u8,
    ctx: *EngineCtx,
    out: *?*session_mod.Session,
    tc_out: *?*tcp.TcpConn,
) void {
    const tc = relay.dialMarker(alloc, addr, marker) catch return;
    tc_out.* = tc;
    out.* = session_mod.Session.establish(
        alloc,
        tc.conn(),
        role,
        id,
        peer_bundle,
        eph,
        @ptrCast(&wrap_slot),
        wrapConn,
        .{ .ctx = ctx, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
        io_g.stored,
    ) catch null;
}

test "relay: присутствие — переподключение без инвайта (контакт-секрет)" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    io_g.stored = io;
    io_g.alloc = alloc;
    obf_idx = 0;
    obf_tracker = @splat(null);

    // relay на loopback: фиксированные порты (SO_REUSEADDR), слушает вечно
    var addr_buf: [24]u8 = undefined;
    var relay_len: usize = 0;
    var srv: ?tcp.Listener = null;
    for ([_]u16{ 39231, 39247, 39283, 39319 }) |port| {
        relay_len = (std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port}) catch unreachable).len;
        srv = tcp.listen(addr_buf[0..relay_len]) catch null;
        if (srv != null) break;
    }
    var listener = srv orelse return error.NoRelay;
    // поток релея с флагом остановки: в конце закрываем слушатель и
    // дожидаемся выхода (map/entries освобождаются в serve)
    var relay_stop = std.atomic.Value(bool).init(false);
    const th = try std.Thread.spawn(.{}, relay.serve, .{ alloc, &listener, &relay_stop });
    const relay_addr = addr_buf[0..relay_len];

    const id_a = try identity.Identity.fromSeed(filled(41));
    const id_b = try identity.Identity.fromSeed(filled(43));

    var ha = Harness{ .alloc = alloc };
    var hb = Harness{ .alloc = alloc };

    var eng_a = shopot.core.engine.Engine.init(alloc, io, id_a, .{ .ctx = &ha, .onText = eng_events.onText });
    var eng_b = shopot.core.engine.Engine.init(alloc, io, id_b, .{ .ctx = &hb, .onText = eng_events.onText });
    const idx_b = try eng_a.addContact("b", id_b.bundle());
    _ = try eng_b.addContact("a", id_a.bundle());
    const cid_b: i64 = @intCast(idx_b + 1);

    // marker из ДОЛГОСРОЧНОГО контакт-секрета (статик-статик X25519):
    // обе стороны без обмена, без нового инвайта
    const sec = try id_a.pairSecret(id_b.bundle());
    const sec_b = try id_b.pairSecret(id_a.bundle());
    try std.testing.expectEqualSlices(u8, &sec, &sec_b);
    const marker = relay.presenceMarker(sec);
    const a_init = std.mem.order(u8, &id_a.bundle(), &id_b.bundle()) == .lt;

    var ctx_a = EngineCtx{ .engine = &eng_a, .contact_id = cid_b, .harness = &ha };
    var ctx_b = EngineCtx{ .engine = &eng_b, .contact_id = 1, .harness = &hb };

    var conns: std.ArrayListUnmanaged(*tcp.TcpConn) = .empty;
    defer conns.deinit(alloc);

    // цикл 1 и цикл 2: «обе стороны онлайн» -> спаривание -> сессия;
    // после разрыва слот освобождается и спаривание происходит СНОВА
    for (0..2) |cycle| {
        var sa_opt: ?*session_mod.Session = null;
        var sb_opt: ?*session_mod.Session = null;
        var tca_opt: ?*tcp.TcpConn = null;
        var tcb_opt: ?*tcp.TcpConn = null;
        const role_a: session_mod.HandshakeRole = if (a_init) .initiator else .responder;
        const role_b: session_mod.HandshakeRole = if (a_init) .responder else .initiator;
        const th_b = try std.Thread.spawn(.{}, relayPresenceSide, .{
            alloc,      &id_b,  id_a.bundle(), filled(@intCast(12 + cycle)), role_b,
            relay_addr, marker, &ctx_b,        &sb_opt,                      &tcb_opt,
        });
        // A-сторона: dial с ретраем (слот мог ещё не освободиться после
        // прошлого цикла — релей снимает регистрацию асинхронно)
        var sa: *session_mod.Session = undefined;
        var tca: *tcp.TcpConn = undefined;
        var a_ok = false;
        for (0..50) |_| {
            relayPresenceSide(alloc, &id_a, id_b.bundle(), filled(@intCast(11 + cycle)), role_a, relay_addr, marker, &ctx_a, &sa_opt, &tca_opt);
            if (sa_opt != null) {
                a_ok = true;
                sa = sa_opt.?;
                tca = tca_opt.?;
                break;
            }
            // неудачная попытка (слот ещё занят): коннект убрать
            if (tca_opt) |tc| {
                tc.deinit();
                alloc.destroy(tc);
                tca_opt = null;
            }
            std.Io.sleep(io, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .awake) catch {};
        }
        th_b.join();
        try std.testing.expect(a_ok);
        const sb = sb_opt orelse return error.ResponderFailed;
        conns.append(alloc, tca) catch return error.OutOfMemory;
        conns.append(alloc, tcb_opt.?) catch return error.OutOfMemory;
        eng_mu.lockUncancelable(io);
        eng_a.sessions.put(cid_b, sa) catch return error.OutOfMemory;
        eng_b.sessions.put(1, sb) catch return error.OutOfMemory;
        eng_mu.unlock(io);

        // лишний коннект при активной паре закрывается релеем
        var extra: ?*session_mod.Session = null;
        var extra_tc: ?*tcp.TcpConn = null;
        var extra_err = false;
        relayPresenceSide(alloc, &id_a, id_b.bundle(), filled(90), .initiator, relay_addr, marker, &ctx_a, &extra, &extra_tc);
        if (extra == null) {
            extra_err = true;
            if (extra_tc) |et| {
                et.deinit();
                alloc.destroy(et);
            }
        }
        try std.testing.expect(extra_err);

        // текст ходит в обе стороны через relay-сплит
        eng_mu.lockUncancelable(io);
        _ = eng_a.sendText(cid_b, "pres-a", &.{}) catch return error.Internal;
        eng_mu.unlock(io);
        try waitTexts(&hb, "pres-a");
        eng_mu.lockUncancelable(io);
        _ = eng_b.sendText(1, "pres-b", &.{}) catch return error.Internal;
        eng_mu.unlock(io);
        try waitTexts(&ha, "pres-b");

        // разрыв: релей освободит слот, следующий цикл спарит заново
        eng_mu.lockUncancelable(io);
        _ = eng_a.sessions.remove(cid_b);
        _ = eng_b.sessions.remove(1);
        eng_mu.unlock(io);
        sa.close();
        sb.close();
        alloc.destroy(sa);
        alloc.destroy(sb);
        std.Io.sleep(io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .awake) catch {};
    }

    eng_a.deinit();
    eng_b.deinit();
    for (conns.items) |tc| {
        alloc.destroy(tc);
    }
    for (obf_tracker) |oc| {
        if (oc) |o| {
            o.deinit();
            alloc.destroy(o);
        }
    }
    for (ha.texts.items) |t| alloc.free(t);
    for (hb.texts.items) |t| alloc.free(t);
    ha.texts.deinit(alloc);
    hb.texts.deinit(alloc);
    ha.reacts.deinit(alloc);
    hb.reacts.deinit(alloc);
    ha.pings.deinit(alloc);
    hb.pings.deinit(alloc);

    // релей: остановить — shutdown на слушающем сокете будит заблоки-
    // рованный accept (close fd его НЕ будит), флаг завершит цикл
    relay_stop.store(true, .seq_cst);
    _ = std.os.linux.shutdown(listener.fd, std.os.linux.SHUT.RDWR);
    th.join();
    listener.deinit();
}

// ------------------------------------------------- file transfer (E2E)

/// Контекст приёма/отправки файла для E2E: приёмник копит чанки и шлёт
/// FILE_ACK каждые 4 (и финальный), отправитель ждёт FILE_SENT.
/// accept=false — имитация «пир не принял ни одного чанка до разрыва».
const FileCtx = struct {
    eng: *shopot.core.engine.Engine, // приёмник: отвечает FILE_ACK
    cid: i64, // cid отправителя в реестре ПРИЁМНИКА
    alloc: std.mem.Allocator,
    buf: std.ArrayListUnmanaged(u8) = .empty,
    expected_seq: u32 = 0,
    size: u32 = 0,
    done: bool = false, // приёмник собрал всё
    sent: bool = false, // отправитель получил FILE_SENT
    accept: bool = true, // phase 1: false — чанки молча роняем

    fn onMeta(ctx: *anyopaque, _: *const shopot.core.engine.Contact, meta: envelope.FileMeta) void {
        const self: *FileCtx = @ptrCast(@alignCast(ctx));
        self.size = meta.size;
        // позиционный ответ на META: сколько УЖЕ принято
        const got: u32 = if (self.buf.items.len >= meta.size)
            @intCast(@divTrunc(@as(u64, meta.size) + envelope.max_file_chunk - 1, envelope.max_file_chunk))
        else
            self.expected_seq;
        self.eng.sendFileAck(self.cid, meta.file_id, got) catch {};
    }

    fn onData(ctx: *anyopaque, _: *const shopot.core.engine.Contact, data: envelope.FileData) void {
        const self: *FileCtx = @ptrCast(@alignCast(ctx));
        if (!self.accept) return; // «пир был оффлайн»: кадры потеряны
        if (data.seq != self.expected_seq) return; // дубликат окна
        self.expected_seq += 1;
        self.buf.appendSlice(self.alloc, data.data) catch return;
        if (self.expected_seq % 4 == 0 or self.buf.items.len >= self.size) {
            self.eng.sendFileAck(self.cid, data.file_id, self.expected_seq) catch {};
        }
        if (self.buf.items.len == self.size) self.done = true;
    }

    fn onSent(ctx: *anyopaque, _: *const shopot.core.engine.Contact, _: [16]u8, _: u32, _: []const u8) void {
        const self: *FileCtx = @ptrCast(@alignCast(ctx));
        self.sent = true;
    }
};

test "files: FILE_ACK-докачка после разрыва сессии, FILE_SENT" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    io_g.stored = io;
    io_g.alloc = alloc;
    obf_idx = 0;
    obf_tracker = @splat(null);

    const id_a = try identity.Identity.fromSeed(filled(31));
    const id_b = try identity.Identity.fromSeed(filled(33));
    const pair = try pipePair(alloc);
    var ca = pair[0];
    var cb = pair[1];

    var fctx = FileCtx{ .eng = undefined, .cid = 1, .alloc = alloc, .accept = false };
    var ha = Harness{ .alloc = alloc }; // не используется, поле EngineCtx

    var eng_a = shopot.core.engine.Engine.init(alloc, io, id_a, .{
        .ctx = &fctx,
        .onFileSent = FileCtx.onSent,
    });
    var eng_b = shopot.core.engine.Engine.init(alloc, io, id_b, .{
        .ctx = &fctx,
        .onFileMeta = FileCtx.onMeta,
        .onFileData = FileCtx.onData,
    });
    fctx.eng = &eng_b; // приёмник отвечает ACK-ами через свою сессию

    const idx_b = try eng_a.addContact("b", id_b.bundle());
    _ = try eng_b.addContact("a", id_a.bundle());
    const cid_b: i64 = @intCast(idx_b + 1);

    var ctx_a = EngineCtx{ .engine = &eng_a, .contact_id = cid_b, .harness = &ha };
    var ctx_b = EngineCtx{ .engine = &eng_b, .contact_id = 1, .harness = &ha };

    var sb_opt: ?*session_mod.Session = null;
    const th_b = try std.Thread.spawn(.{}, establishEngineB, .{ alloc, cb.conn(), &id_b, id_a.bundle(), &ctx_b, &sb_opt });
    const sa = try session_mod.Session.establish(
        alloc,
        ca.conn(),
        .initiator,
        &id_a,
        id_b.bundle(),
        filled(2),
        @ptrCast(&wrap_slot),
        wrapConn,
        .{ .ctx = &ctx_a, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
        io,
    );
    th_b.join();
    const sb = sb_opt orelse return error.ResponderFailed;
    eng_a.sessions.put(cid_b, sa) catch return error.OutOfMemory;
    eng_b.sessions.put(1, sb) catch return error.OutOfMemory;

    // 150000 байт = 10 чанков; приёмник «мертв» (accept=false) — окно
    // выкачивается без единого ACK и передача встаёт
    const bytes: [150_000]u8 = @splat(0x5C);
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &sha, .{});
    const file_id = sha[0..16].*;
    eng_mu.lockUncancelable(io);
    const oc = try eng_a.sendFile(cid_b, file_id, "blob.bin", &bytes, sha);
    eng_mu.unlock(io);
    try std.testing.expectEqual(shopot.core.engine.Engine.SendResult.sent, oc.result);
    // жрём кадры приёмником (роняем) — передача НЕ завершается
    std.Io.sleep(io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .awake) catch {};
    try std.testing.expect(!fctx.sent);

    // разрыв сессии и реконнект на НОВОЙ паре труб
    sa.close();
    sb.close();
    const pair2 = try pipePair(alloc);
    var ca2 = pair2[0];
    var cb2 = pair2[1];
    var sb2_opt: ?*session_mod.Session = null;
    const th_b2 = try std.Thread.spawn(.{}, establishEngineB, .{ alloc, cb2.conn(), &id_b, id_a.bundle(), &ctx_b, &sb2_opt });
    const sa2 = try session_mod.Session.establish(
        alloc,
        ca2.conn(),
        .initiator,
        &id_a,
        id_b.bundle(),
        filled(3),
        @ptrCast(&wrap_slot),
        wrapConn,
        .{ .ctx = &ctx_a, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
        io,
    );
    th_b2.join();
    const sb2 = sb2_opt orelse return error.ResponderFailed;
    eng_a.sessions.put(cid_b, sa2) catch return error.OutOfMemory;
    eng_b.sessions.put(1, sb2) catch return error.OutOfMemory;

    // сессия поднялась: движок возобновляет с last_ack (0 — подтверждений
    // не было), приёмник «ожил» и теперь принимает + ACK-ает
    fctx.accept = true;
    eng_mu.lockUncancelable(io);
    eng_a.resumeFileTx(cid_b);
    eng_mu.unlock(io);

    var ok = false;
    for (0..500) |_| {
        if (fctx.sent and fctx.done) {
            ok = true;
            break;
        }
        std.Io.sleep(io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
    }
    try std.testing.expect(ok);
    try std.testing.expectEqual(@as(usize, bytes.len), fctx.buf.items.len);
    try std.testing.expectEqualSlices(u8, &bytes, fctx.buf.items);

    // после завершения запись передачи погашена
    eng_mu.lockUncancelable(io);
    const txn = eng_a.file_tx.items.len;
    eng_mu.unlock(io);
    try std.testing.expectEqual(@as(usize, 0), txn);

    sa2.close();
    sb2.close();
    alloc.destroy(sa);
    alloc.destroy(sb);
    alloc.destroy(sa2);
    alloc.destroy(sb2);
    for (obf_tracker) |oc2| {
        if (oc2) |o| {
            o.deinit();
            alloc.destroy(o);
        }
    }
    // сессии уже закрыты и освобождены: из карт движка — ДО deinit
    // (deinit закрывает всё, что осталось в карте)
    _ = eng_a.sessions.remove(cid_b);
    _ = eng_b.sessions.remove(1);
    eng_a.deinit();
    eng_b.deinit();
    fctx.buf.deinit(alloc);
    drainPipe(ca.me);
    drainPipe(cb.me);
    drainPipe(ca2.me);
    drainPipe(cb2.me);
    ca.me.inbox.deinit(alloc);
    cb.me.inbox.deinit(alloc);
    ca2.me.inbox.deinit(alloc);
    cb2.me.inbox.deinit(alloc);
    alloc.destroy(ca.me);
    alloc.destroy(cb.me);
    alloc.destroy(ca2.me);
    alloc.destroy(cb2.me);
}

/// establishB-вариант с EngineCtx (file/outbox E2E): респондер на своём
/// потоке, конверты идут в engineDispatch движка.
fn establishEngineB(
    alloc: std.mem.Allocator,
    conn: interfaces.Conn,
    id_b: *const identity.Identity,
    peer_bundle: [64]u8,
    ctx: *EngineCtx,
    out: *?*session_mod.Session,
) void {
    out.* = session_mod.Session.establish(
        alloc,
        conn,
        .responder,
        id_b,
        peer_bundle,
        filled(2),
        @ptrCast(&wrap_slot),
        wrapConn,
        .{ .ctx = ctx, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
        io_g.stored,
    ) catch null;
}

test "outbox: очередь офлайн, доставка при сессии, ACK, дедуп" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    io_g.stored = io;
    io_g.alloc = alloc;

    obf_idx = 0;
    obf_tracker = @splat(null);
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

    // 1) офлайн: TEXT с форматированием уходит в очередь, не в ошибку
    const fmt = [_]envelope.TextEntity{
        .{ .kind = .bold, .offset = 0, .len = 7 }, // «offline»
        .{ .kind = .spoiler, .offset = 8, .len = 6 }, // «digest»
    };
    const ocq = try eng_b.sendText(1, "offline-digest", &fmt);
    try std.testing.expectEqual(shopot.core.engine.Engine.SendResult.queued, ocq.result);
    try std.testing.expectEqual(@as(usize, 1), eng_b.outbox.items.len);

    // 2) поднимаем сессии
    var sb_opt: ?*session_mod.Session = null;
    const th_b = try std.Thread.spawn(.{}, struct {
        fn go(conn: interfaces.Conn, id_b_ptr: *const identity.Identity, peer_bundle: [64]u8, ctx: *EngineCtx, out: *?*session_mod.Session) void {
            out.* = session_mod.Session.establish(
                io_g.alloc,
                conn,
                .responder,
                id_b_ptr,
                peer_bundle,
                filled(6),
                @ptrCast(&wrap_slot),
                wrapConn,
                .{ .ctx = ctx, .onEnvelope = engineDispatch, .onClosed = Harness.onClosed },
                io_g.stored,
            ) catch null;
        }
    }.go, .{ cb.conn(), &id_b, id_a.bundle(), &ctx_b, &sb_opt });

    const sa = try session_mod.Session.establish(
        alloc,
        ca.conn(),
        .initiator,
        &id_a,
        id_b.bundle(),
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
    // entities пережили очередь: тот же хвост дошёл до onText у A
    {
        var out: [envelope.max_text_entities]envelope.TextEntity = undefined;
        const tail = ha.ent_tails[0][0..ha.ent_tail_lens[0]];
        const n = try envelope.parseEntities(tail, "offline-digest".len, &out);
        try std.testing.expectEqual(@as(usize, 2), n);
        try std.testing.expectEqual(envelope.EntityKind.bold, out[0].kind);
        try std.testing.expectEqual(@as(u16, 0), out[0].offset);
        try std.testing.expectEqual(envelope.EntityKind.spoiler, out[1].kind);
        try std.testing.expectEqual(@as(u16, 8), out[1].offset);
        try std.testing.expectEqual(@as(u16, 6), out[1].len);
    }

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

    // 6) форматирование с value: link доходит вместе с URL (B -> A, онлайн)
    const link_ents = [_]envelope.TextEntity{
        .{ .kind = .link, .offset = 0, .len = 3, .value = "https://shopot.local" },
    };
    _ = try eng_b.sendText(1, "tot", &link_ents);
    try waitTexts(&ha, "tot");
    {
        const li = ha.texts.items.len - 1;
        var lout: [envelope.max_text_entities]envelope.TextEntity = undefined;
        const ltail = ha.ent_tails[li][0..ha.ent_tail_lens[li]];
        const ln = try envelope.parseEntities(ltail, "tot".len, &lout);
        try std.testing.expectEqual(@as(usize, 1), ln);
        try std.testing.expectEqual(envelope.EntityKind.link, lout[0].kind);
        try std.testing.expectEqual(@as(u16, 3), lout[0].len);
        try std.testing.expectEqualStrings("https://shopot.local", lout[0].value);
    }

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
