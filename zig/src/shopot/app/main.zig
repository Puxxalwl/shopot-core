//! shopot-zig CLI: тонкий REPL над ядром. Только std, никаких JSON.
//! Контакты и блокировки живут в шифрованном логе (~/.shopot/zig-log).
const std = @import("std");
const shopot = @import("shopot");

const identity = shopot.crypto.identity;
const engine_mod = shopot.core.engine;
const session_mod = shopot.core.session;
const envelope = shopot.proto.envelope;
const hb = shopot.net.heartbeat;
const obf = shopot.net.obfuscate;
const tcp = shopot.net.tcp;
const store_mod = shopot.store.log;
const interfaces = shopot.core.interfaces;

const usage =
    \\shopot-zig — шифрованный мессенджер (std-only Zig)
    \\
    \\  init                        создать личность (~/.shopot/zig-seed, 0600)
    \\  id                          показать bundle и отпечаток
    \\  add <имя> <bundle-hex>      добавить контакт (hex 128 символов из `id`)
    \\  contacts                    список контактов
    \\  listen <addr:port> <id>     ждать этого контакта (сессия responder)
    \\  connect <addr:port> <id>    подключиться к контакту
    \\  msg <id> <текст>            отправить сообщение
    \\  react <id> <hex32> <код>    реакция на msg_id (hex 32)
    \\  block <id> / unblock <id>   блокировка
    \\  quit                        выход
;

fn shopotDir(io: std.Io, home: []const u8) ![512]u8 {
    if (home.len == 0) return error.NoHome;
    var buf: [512]u8 = undefined;
    std.Io.Dir.createDirAbsolute(io, try std.fmt.bufPrint(&buf, "{s}/.shopot", .{home}), .default_dir) catch {};
    return buf;
}

fn loadSeed(io: std.Io, home: []const u8) ![32]u8 {
    _ = try shopotDir(io, home);
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/.shopot/zig-seed", .{home});
    const f = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_only });
    defer f.close(io);
    var seed: [32]u8 = undefined;
    const n = try f.readPositionalAll(io, &seed, 0);
    if (n != 32) return error.BadSeed;
    return seed;
}

fn saveSeed(io: std.Io, home: []const u8, seed: [32]u8) !void {
    _ = try shopotDir(io, home);
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/.shopot/zig-seed", .{home});
    const f = try std.Io.Dir.createFileAbsolute(io, path, .{ .exclusive = true });
    defer f.close(io);
    try f.writePositionalAll(io, &seed, 0);
    f.setPermissions(io, .fromMode(0o600)) catch {};
}

fn toHex(out: []u8, bytes: []const u8) ![]u8 {
    var n: usize = 0;
    for (bytes) |b| {
        const p = try std.fmt.bufPrint(out[n..], "{x:0>2}", .{b});
        n += p.len;
    }
    return out[0..n];
}

fn parseHex16(hex: []const u8) ![16]u8 {
    if (hex.len != 32) return error.BadHex;
    var out: [16]u8 = undefined;
    for (0..16) |i| out[i] = try std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16);
    return out;
}

fn parseHex64(hex: []const u8) ![64]u8 {
    if (hex.len != 128) return error.BadHex;
    var out: [64]u8 = undefined;
    for (0..64) |i| out[i] = try std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16);
    return out;
}

// ------------------------------------------------------------------ app
const App = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    id: *identity.Identity,
    eng: *engine_mod.Engine,
    log: ?*store_mod.Log = null,
    hb: std.AutoHashMap(i64, hb.State),
    sess_ctx: std.AutoHashMap(i64, *SessCtx),
    raw_conns: std.ArrayListUnmanaged(*tcp.TcpConn) = .empty,
    obfs: std.ArrayListUnmanaged(*obf.ObfConn) = .empty,
    mu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    running: bool = true,

    /// Спин-блок: держится микросекунды (append в список), потоков мало.
    fn lock(self: *App) void {
        while (self.mu.swap(true, .acquire)) std.Thread.yield() catch {};
    }
    fn unlock(self: *App) void {
        self.mu.store(false, .release);
    }

    /// Время — прямой syscall: НЕ трогаем io, чтобы не конкурировать
    /// с сетевыми операциями из других потоков (Threaded io).
    fn nowMs(self: *App) i64 {
        _ = self;
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.REALTIME, &ts);
        return @as(i64, @intCast(ts.sec)) * 1000 + @as(i64, @intCast(@divTrunc(ts.nsec, std.time.ns_per_ms)));
    }

    /// Привязать сессию к контакту. sc — контекст событий, уже создан и
    /// используется rx-потоком сессии, поэтому здесь не уничтожается никогда
    /// (короткоживущий процесс, счёт контекстов равен числу сессий).
    fn bindSession(self: *App, cid: i64, s: *session_mod.Session, sc: *SessCtx) !void {
        self.lock();
        defer self.unlock();
        if (self.eng.sessions.get(cid)) |old| {
            old.close();
            self.eng.alloc.destroy(old);
        }
        try self.eng.sessions.put(cid, s);
        try self.sess_ctx.put(cid, sc);
        // prime presence: считаем контакт живым сразу после рукопожатия
        const now = self.nowMs();
        self.eng.markSeen(cid, now);
        if (self.hb.getPtr(cid)) |st| st.onInbound(now);
    }

    fn events(self: *App) engine_mod.Events {
        return .{ .ctx = self, .onText = onTextEv, .onReaction = onReactionEv, .onPresence = onPresenceEv, .onBlockedNotice = onBlockedEv };
    }
};

const SessCtx = struct {
    app: *App,
    cid: i64,
};

fn envIn(ctx: *anyopaque, env: envelope.Envelope) void {
    const sc: *SessCtx = @ptrCast(@alignCast(ctx));
    const app = sc.app;
    const now = app.nowMs();
    app.lock();
    defer app.unlock();
    app.eng.markSeen(sc.cid, now);
    if (app.hb.getPtr(sc.cid)) |st| {
        st.onInbound(now);
        switch (env) {
            .presence_pong => |pp| st.onPong(pp.seq, now),
            else => {},
        }
    }
    app.eng.dispatch(sc.cid, env);
}

fn onClosed(ctx: *anyopaque) void {
    _ = ctx;
}

fn onTextEv(_: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8, _: i64, body: []const u8) void {
    var hex_buf: [32]u8 = undefined;
    var hx: []const u8 = "?";
    _ = toHex(&hex_buf, &msg_id) catch {};
    hx = hex_buf[0..];
    std.debug.print("\n<< [{s}] {s}  (msg {s})\n> ", .{ from.getName(), body, hx });
}

fn onReactionEv(_: *anyopaque, from: *const engine_mod.Contact, r: engine_mod.Reaction) void {
    var hex_buf: [32]u8 = undefined;
    std.debug.print("\n<< [{s}] реакция {d} на {s}\n> ", .{ from.getName(), r.code, toHex(&hex_buf, &r.msg_id) catch "?" });
}

fn onPresenceEv(_: *anyopaque, from: *const engine_mod.Contact, online: bool, _: i64) void {
    std.debug.print("\n<< [{s}] {s}\n> ", .{ from.getName(), if (online) "online" else "offline" });
}

fn onBlockedEv(_: *anyopaque, from: *const engine_mod.Contact) void {
    std.debug.print("\n<< [{s}] заблокировал вас\n> ", .{from.getName()});
}

fn wrapConn(ctx: *anyopaque, raw: interfaces.Conn, keys: shopot.crypto.handshake.SessionKeys, alloc: std.mem.Allocator) anyerror!interfaces.Conn {
    const app: *App = @ptrCast(@alignCast(ctx));
    var key: [32]u8 = undefined;
    shopot.crypto.kdf.expand(keys.transcript, "shopot-obf-v3", &key);
    const oc = try alloc.create(obf.ObfConn);
    oc.* = try obf.ObfConn.init(alloc, app.io, raw, &key);
    app.lock();
    defer app.unlock();
    try app.obfs.append(alloc, oc);
    return obf.obfConn(oc);
}

// ------------------------------------------------------- heartbeat ticker
fn tickerLoop(app: *App) void {
    while (app.running) {
        const req: std.os.linux.timespec = .{ .sec = 0, .nsec = 250 * std.time.ns_per_ms };
        _ = std.os.linux.nanosleep(&req, null);
        app.lock();
        defer app.unlock();
        var it = app.hb.iterator();
        const now = app.nowMs();
        while (it.next()) |e| {
            const cid = e.key_ptr.*;
            const st = e.value_ptr;
            const s = app.eng.sessions.get(cid) orelse continue;
            switch (st.tick(now)) {
                .none => {},
                .send_ping => |p| s.sendEnvelope(.{ .presence_ping = .{
                    .seq = p.seq,
                    .ts_ms = @intCast(p.ts_ms),
                } }) catch {},
                .mark_offline => {
                    app.eng.contacts.items[@intCast(cid - 1)].online = false;
                    if (app.eng.ev.onPresence) |cb|
                        cb(app.eng.ev.ctx, &app.eng.contacts.items[@intCast(cid - 1)], false, now);
                },
            }
        }
    }
}

// ------------------------------------------------------------- commands
fn cmdAdd(app: *App, args: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, args, " ");
    const name = it.next() orelse return error.BadArgs;
    const hex = it.next() orelse return error.BadArgs;
    const bundle = try parseHex64(hex);
    const idx = try app.eng.addContact(name, bundle);
    const cid: i64 = @intCast(idx + 1);
    try app.hb.put(cid, .{});
    if (app.log) |log| {
        var buf: [97]u8 = undefined;
        buf[0] = @intCast(name.len);
        @memcpy(buf[1 .. 1 + name.len], name);
        @memcpy(buf[1 + name.len .. 1 + name.len + 64], &bundle);
        _ = log.append(.contact, buf[0 .. 1 + name.len + 64]) catch {};
    }
    std.debug.print("контакт {s} = id {d}\n", .{ name, cid });
}

fn cmdContacts(app: *App) void {
    app.lock();
    defer app.unlock();
    const now = app.nowMs();
    for (app.eng.contacts.items, 0..) |c, i| {
        const cid: i64 = @intCast(i + 1);
        const seen: ?i64 = app.eng.lastSeen(cid);
        const ago = if (seen) |s| now - s else -1;
        std.debug.print("  id {d}: {s} {s}{s} (last seen: {d} ms назад)\n", .{
            cid,
            c.getName(),
            if (c.online) "[online]" else "[offline]",
            if (c.blocked) " [BLOCKED]" else "",
            ago,
        });
    }
}

fn establishTo(app: *App, addr: []const u8, cid: i64, role: session_mod.HandshakeRole) !void {
    const idx: usize = @intCast(cid - 1);
    if (idx >= app.eng.contacts.items.len) return error.NoContact;
    const bundle = app.eng.contacts.items[idx].bundle;
    const tc = try tcp.dial(app.alloc, addr);
    {
        app.lock();
        defer app.unlock();
        try app.raw_conns.append(app.alloc, tc);
    }
    var eph: [32]u8 = undefined;
    app.io.random(&eph);
    const sc = try app.alloc.create(SessCtx);
    sc.* = .{ .app = app, .cid = cid };
    const s = session_mod.Session.establish(
        app.alloc,
        tc.conn(),
        role,
        app.id,
        bundle[32..64].*,
        eph,
        app,
        wrapConn,
        .{ .ctx = sc, .onEnvelope = envIn, .onClosed = onClosed },
        app.io,
    ) catch |e| {
        app.alloc.destroy(sc);
        return e;
    };
    try app.bindSession(cid, s, sc);
}

fn acceptLoop(app: *App, listener: *tcp.Listener, cid: i64) void {
    while (app.running) {
        const tc = listener.accept(app.alloc) catch break;
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                continue;
            };
        }
        const idx: usize = @intCast(cid - 1);
        const bundle = app.eng.contacts.items[idx].bundle;
        var eph: [32]u8 = undefined;
        app.io.random(&eph);
        const sc = app.alloc.create(SessCtx) catch {
            tc.deinit();
            continue;
        };
        sc.* = .{ .app = app, .cid = cid };
        const s = session_mod.Session.establish(
            app.alloc,
            tc.conn(),
            .responder,
            app.id,
            bundle[32..64].*,
            eph,
            app,
            wrapConn,
            .{ .ctx = sc, .onEnvelope = envIn, .onClosed = onClosed },
            app.io,
        ) catch {
            app.alloc.destroy(sc);
            std.debug.print("<< рукопожатие не удалось\n> ", .{});
            continue;
        };
        app.bindSession(cid, s, sc) catch {};
        std.debug.print("<< сессия установлена: {s}\n> ", .{app.eng.contacts.items[idx].getName()});
    }
}

fn cmdMsg(app: *App, args: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, args, " ");
    const id_str = it.next() orelse return error.BadArgs;
    const body = it.rest();
    if (body.len == 0) return error.BadArgs;
    const cid = try std.fmt.parseInt(i64, id_str, 10);
    app.lock();
    defer app.unlock();
    try app.eng.sendText(cid, body);
}

fn cmdReact(app: *App, args: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, args, " ");
    const id_str = it.next() orelse return error.BadArgs;
    const mid_hex = it.next() orelse return error.BadArgs;
    const code_str = it.next() orelse return error.BadArgs;
    const cid = try std.fmt.parseInt(i64, id_str, 10);
    const mid = try parseHex16(mid_hex);
    const code = try std.fmt.parseInt(u8, code_str, 10);
    app.lock();
    defer app.unlock();
    try app.eng.react(cid, mid, envelope.react_add, code);
}

fn cmdBlock(app: *App, args: []const u8, flag: bool) !void {
    const cid = try std.fmt.parseInt(i64, std.mem.trim(u8, args, " "), 10);
    app.lock();
    defer app.unlock();
    if (flag) {
        try app.eng.block(cid);
        if (app.log) |log| {
            var buf: [65]u8 = undefined;
            @memcpy(buf[0..64], &app.eng.contacts.items[@intCast(cid - 1)].bundle);
            buf[64] = 1;
            _ = log.append(.block, &buf) catch {};
        }
    } else {
        try app.eng.unblock(cid);
        if (app.log) |log| {
            var buf: [65]u8 = undefined;
            @memcpy(buf[0..64], &app.eng.contacts.items[@intCast(cid - 1)].bundle);
            buf[64] = 0;
            _ = log.append(.block, &buf) catch {};
        }
    }
}

fn loadContacts(app: *App) void {
    const log = app.log orelse return;
    const recs = log.readAll(.contact, app.alloc) catch return;
    defer {
        for (recs) |r| app.alloc.free(r);
        app.alloc.free(recs);
    }
    for (recs) |rec| {
        if (rec.len < 66) continue;
        const nlen: usize = rec[0];
        if (rec.len < 1 + nlen + 64) continue;
        const name = rec[1 .. 1 + nlen];
        const bundle: [64]u8 = rec[1 + nlen ..][0..64].*;
        const idx = app.eng.addContact(name, bundle) catch continue;
        app.hb.put(@intCast(idx + 1), .{}) catch {};
    }
    // блокировки поверх загруженных контактов
    const blocks = log.readAll(.block, app.alloc) catch return;
    defer {
        for (blocks) |r| app.alloc.free(r);
        app.alloc.free(blocks);
    }
    for (blocks) |rec| {
        if (rec.len != 65) continue;
        const bundle: [64]u8 = rec[0..64].*;
        const flag = rec[64] == 1;
        for (app.eng.contacts.items) |*c| {
            if (std.mem.eql(u8, &c.bundle, &bundle)) c.blocked = flag;
        }
    }
}

/// Построчное чтение stdin: readStreaming может вернуть 0 без данных —
/// тогда короткий сон и повтор. EndOfStream только на настоящем закрытии.
fn readLine(buf: []u8) ![]u8 {
    var n: usize = 0;
    while (true) {
        if (n == buf.len) return error.StreamTooLong;
        const got = std.posix.read(0, buf[n..]) catch |e| switch (e) {
            error.WouldBlock => {
                std.Thread.yield() catch {};
                continue;
            },
            else => return e,
        };
        if (got == 0) return error.EndOfStream;
        if (std.mem.indexOfScalar(u8, buf[n .. n + got], '\n')) |ix| {
            return buf[0 .. n + ix];
        }
        n += got;
    }
}

var stdin_file: std.Io.File = undefined;

fn repl(app: *App) !void {
    stdin_file = std.Io.File.stdin();
    var line_buf: [2048]u8 = undefined;

    std.debug.print("готов. помощь:\n{s}\n", .{usage});
    var prompt_visible = true;
    while (app.running) {
        if (prompt_visible) std.debug.print("> ", .{});
        const line = readLine(&line_buf) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) {
            prompt_visible = false;
            continue;
        }
        prompt_visible = true;

        var it = std.mem.tokenizeAny(u8, trimmed, " ");
        const cmd = it.next() orelse continue;
        const rest = std.mem.trim(u8, trimmed[cmd.len..], " ");

        if (std.mem.eql(u8, cmd, "quit") or std.mem.eql(u8, cmd, "q")) {
            app.running = false;
        } else if (std.mem.eql(u8, cmd, "contacts")) {
            cmdContacts(app);
        } else if (std.mem.eql(u8, cmd, "add")) {
            cmdAdd(app, rest) catch |e| std.debug.print("ошибка: {s}\n", .{@errorName(e)});
        } else if (std.mem.eql(u8, cmd, "msg")) {
            cmdMsg(app, rest) catch |e| std.debug.print("ошибка: {s}\n", .{@errorName(e)});
        } else if (std.mem.eql(u8, cmd, "react")) {
            cmdReact(app, rest) catch |e| std.debug.print("ошибка: {s}\n", .{@errorName(e)});
        } else if (std.mem.eql(u8, cmd, "block")) {
            cmdBlock(app, rest, true) catch |e| std.debug.print("ошибка: {s}\n", .{@errorName(e)});
        } else if (std.mem.eql(u8, cmd, "unblock")) {
            cmdBlock(app, rest, false) catch |e| std.debug.print("ошибка: {s}\n", .{@errorName(e)});
        } else if (std.mem.eql(u8, cmd, "connect")) {
            var ait = std.mem.tokenizeAny(u8, rest, " ");
            const addr = ait.next() orelse continue;
            const cid = std.fmt.parseInt(i64, ait.next() orelse continue, 10) catch continue;
            establishTo(app, addr, cid, .initiator) catch |e|
                std.debug.print("ошибка: {s}\n", .{@errorName(e)});
        } else if (std.mem.eql(u8, cmd, "listen")) {
            var ait = std.mem.tokenizeAny(u8, rest, " ");
            const addr = ait.next() orelse continue;
            const cid = std.fmt.parseInt(i64, ait.next() orelse continue, 10) catch continue;
            const lsn = tcp.listen(addr) catch |e| {
                std.debug.print("ошибка listen: {s}\n", .{@errorName(e)});
                continue;
            };
            const lp = app.alloc.create(tcp.Listener) catch continue;
            lp.* = lsn;
            const th = std.Thread.spawn(.{}, struct {
                fn go(a: *App, l: *tcp.Listener, c: i64) void {
                    acceptLoop(a, l, c);
                }
            }.go, .{ app, lp, cid }) catch continue;
            th.detach();
            std.debug.print("слушаю {s} для id {d}\n", .{ addr, cid });
        } else {
            std.debug.print("не знаю команду. команды:\n{s}\n", .{usage});
        }
    }
}

pub fn main(start: std.process.Init) !void {
    const io = start.io;
    const home: []const u8 = start.environ_map.get("HOME") orelse "";
    const argv = start.minimal.args.vector;

    if (argv.len < 2) {
        std.debug.print("{s}\n", .{usage});
        return;
    }
    const cmd: []const u8 = std.mem.span(argv[1]);

    if (std.mem.eql(u8, cmd, "init")) {
        var seed: [32]u8 = undefined;
        io.random(&seed);
        try saveSeed(io, home, seed);
        var id = try identity.Identity.fromSeed(seed);
        defer id.deinit();
        var fp_buf: [96]u8 = undefined;
        std.debug.print("identity created, seed saved to ~/.shopot/zig-seed (0600)\nfingerprint: {s}\n", .{try id.fingerprintTo(&fp_buf)});
        return;
    }

    // все остальные команды требуют существующей личности
    const seed = try loadSeed(io, home);
    var id = try identity.Identity.fromSeed(seed);
    defer id.deinit();

    if (std.mem.eql(u8, cmd, "id")) {
        const bundle = id.bundle();
        var hex_buf: [130]u8 = undefined;
        const hx = try toHex(&hex_buf, &bundle);
        var fp_buf: [96]u8 = undefined;
        std.debug.print("bundle(hex): {s}\nfingerprint: {s}\n", .{ hx, try id.fingerprintTo(&fp_buf) });
        return;
    }

    if (std.mem.eql(u8, cmd, "chat")) {
        // потоки: rx-сессий, тикер presence, accept-loop — аллокатор общий
        var dbg_state = std.heap.DebugAllocator(.{ .thread_safe = true }){};
        const alloc = dbg_state.allocator();

        var eng = engine_mod.Engine.init(alloc, io, id, undefined);
        var store_path_buf: [512]u8 = undefined;
        const store_path = try std.fmt.bufPrint(&store_path_buf, "{s}/.shopot/zig-log", .{home});
        var log_ptr: ?*store_mod.Log = null;
        if (store_mod.Log.open(alloc, store_path, &seed)) |l| {
            const lp = try alloc.create(store_mod.Log);
            lp.* = l;
            log_ptr = lp;
        } else |e| {
            std.debug.print("лог не открылся: {s} (продолжаю без хранения)\n", .{@errorName(e)});
        }

        var app = App{
            .alloc = alloc,
            .io = io,
            .id = &id,
            .eng = &eng,
            .log = log_ptr,
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *SessCtx).init(alloc),
        };
        eng.ev = app.events();

        loadContacts(&app);

        const th = std.Thread.spawn(.{}, tickerLoop, .{&app}) catch return error.OutOfMemory;
        th.detach();

        try repl(&app);

        eng.deinit();
        return;
    }

    std.debug.print("{s}\n", .{usage});
}
