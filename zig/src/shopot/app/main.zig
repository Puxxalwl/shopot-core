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
const invite_mod = @import("invite.zig");
const discover_mod = @import("discover.zig");
const tui_mod = @import("tui.zig");
const audio_mod = @import("audio.zig");

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

// ------------------------------------------------------------------ call
/// Активный звонок: одна линия на процесс (v1), состояние под app.mu.
const CallState = struct {
    cid: i64,
    call_id: [16]u8,
    secret: [32]u8,
    seq: u32 = 0,
    /// Гудки/разговор. Установлено после accept.
    up: bool = false,
    pcm: ?audio_mod.PcmPort = null,
    audio_thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

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
    call: ?*CallState = null,
    call_pcm_dir: ?[]const u8 = null,
    listen_port: u16 = 7777,
    // лента чата для TUI: кольцо на 512 строк без аллокаций
    chat_lines: [512]tui_mod.ChatLine = undefined,
    chat_head: usize = 0,
    chat_count: usize = 0,
    tui: bool = false,

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

    /// Добавить строку в ленту (для TUI; REPL печатает напрямую).
    fn pushChat(self: *App, text: []const u8) void {
        const slot = &self.chat_lines[self.chat_head % self.chat_lines.len];
        const n = @min(text.len, slot.text.len);
        @memcpy(slot.text[0..n], text[0..n]);
        slot.len = @intCast(n);
        self.chat_head +%= 1;
        if (self.chat_count < self.chat_lines.len) self.chat_count += 1;
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
        return .{ .ctx = self, .onText = onTextEv, .onReaction = onReactionEv, .onPresence = onPresenceEv, .onBlockedNotice = onBlockedEv, .onCallSignal = onCallSignalEv, .onCallAudio = onCallAudioEv };
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

fn onTextEv(ctx: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8, _: i64, body: []const u8) void {
    var hex_buf: [32]u8 = undefined;
    var hx: []const u8 = "?";
    _ = toHex(&hex_buf, &msg_id) catch {};
    hx = hex_buf[0..];
    const app: *App = @ptrCast(@alignCast(ctx));
    if (app.tui) {
        var line: [300]u8 = undefined;
        const t = std.fmt.bufPrint(&line, "<< {s}: {s} ({s})", .{ from.getName(), body, hx }) catch return;
        app.pushChat(t);
        return;
    }
    std.debug.print("\n<< [{s}] {s}  (msg {s})\n> ", .{ from.getName(), body, hx });
}

fn onReactionEv(ctx: *anyopaque, from: *const engine_mod.Contact, r: engine_mod.Reaction) void {
    var hex_buf: [32]u8 = undefined;
    const app: *App = @ptrCast(@alignCast(ctx));
    if (app.tui) {
        var line: [128]u8 = undefined;
        const t = std.fmt.bufPrint(&line, "<< {s}: реакция {d}", .{ from.getName(), r.code }) catch return;
        app.pushChat(t);
        return;
    }
    std.debug.print("\n<< [{s}] реакция {d} на {s}\n> ", .{ from.getName(), r.code, toHex(&hex_buf, &r.msg_id) catch "?" });
}

fn onPresenceEv(ctx: *anyopaque, from: *const engine_mod.Contact, online: bool, _: i64) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    if (app.tui) {
        var line: [96]u8 = undefined;
        const t = std.fmt.bufPrint(&line, "* {s} {s}", .{ from.getName(), if (online) "online" else "offline" }) catch return;
        app.pushChat(t);
        return;
    }
    std.debug.print("\n<< [{s}] {s}\n> ", .{ from.getName(), if (online) "online" else "offline" });
}

fn onBlockedEv(_: *anyopaque, from: *const engine_mod.Contact) void {
    std.debug.print("\n<< [{s}] заблокировал вас\n> ", .{from.getName()});
}

// ------------------------------------------------------------- звонки
/// Входящий сигнал: offer — гудки, accept — линия вверх, reject/hangup — конец.
fn onCallSignalEv(ctx: *anyopaque, from: *const engine_mod.Contact, op: u8, call_id: [16]u8) void {
    // ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn) — второго захвата быть не должно.
    const app: *App = @ptrCast(@alignCast(ctx));
    switch (op) {
        audio_mod.CallOp.offer => {
            if (app.call) |c| {
                // уже в звонке: отклоняем
                _ = app.eng.callSignal(c.cid, audio_mod.CallOp.reject, call_id) catch {};
                return;
            }
            const cid = contactIdByBundle(app, from.bundle) orelse return;
            const c = app.alloc.create(CallState) catch return;
            const zero_secret: [32]u8 = @splat(0);
            const secret = if (app.eng.sessions.get(cid)) |sess| sess.callSecret(call_id) else zero_secret;
            c.* = .{ .cid = cid, .call_id = call_id, .secret = secret };
            app.call = c;
            std.debug.print("\n<< входящий звонок от {s}: answer {d} — принять, hangup — отклонить\n> ", .{ from.getName(), cid });
        },
        audio_mod.CallOp.accept => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            startCallAudio(app, c);
            std.debug.print("\n<< {s} ответил, линия открыта\n> ", .{from.getName()});
        },
        audio_mod.CallOp.reject => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            endCallLocked(app, "отклонён");
        },
        audio_mod.CallOp.hangup => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            endCallLocked(app, "повесил трубку");
        },
        else => {},
    }
}

/// Входящий аудиокадр: расшифровываем своим контуром и выводим в spk.
fn onCallAudioEv(ctx: *anyopaque, from: *const engine_mod.Contact, seq: u32, data: []const u8) void {
    // ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn) — второго захвата быть не должно.
    const app: *App = @ptrCast(@alignCast(ctx));
    const c = app.call orelse return;
    if (!c.up) return;
    if (c.cid != contactIdByBundle(app, from.bundle) orelse return) return;
    var plain: [audio_mod.frame_bytes]u8 = undefined;
    audio_mod.openFrame(&plain, c.secret, c.call_id, seq, data) catch return;
    if (c.pcm) |*pcm| pcm.writeFrame(&plain);
}

/// Найти cid по bundle (порядок стабильный: contacts[i] — id i+1).
fn contactIdByBundle(app: *App, bundle: [64]u8) ?i64 {
    for (app.eng.contacts.items, 0..) |c, i| {
        if (std.mem.eql(u8, &c.bundle, &bundle)) return @intCast(i + 1);
    }
    return null;
}

/// Открыть аудио (fifo) и запустить поток захвата микрофона.
fn startCallAudio(app: *App, c: *CallState) void {
    if (c.pcm != null) return;
    c.up = true;
    // fifo в ~/.shopot/pcm — файл создаётся при старте чата
    if (app.call_pcm_dir) |dir| {
        if (audio_mod.PcmPort.openFifos(dir)) |p| {
            c.pcm = p;
        } else |_| {}
    }
    c.stop_flag.store(false, .release);
    const th = std.Thread.spawn(.{}, micLoop, .{app}) catch return;
    c.audio_thread = th;
}

/// Поток микрофона: 20 мс кадр -> шифруем -> callAudio. Тишина если fifo пуст.
fn micLoop(app: *App) void {
    // Аккумулятор: fifo может отдавать данные малыми кусками, кадр шлём
    // только целиком (320 байт) — иначе разбор на приёме усложняется.
    var acc: [audio_mod.frame_bytes]u8 = @splat(0);
    var acc_len: usize = 0;
    const sleep: std.os.linux.timespec = .{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
    while (true) {
        _ = std.os.linux.nanosleep(&sleep, null);
        app.lock();
        defer app.unlock();
        const c = app.call orelse break;
        if (c.stop_flag.load(.acquire)) break;
        if (!c.up) continue;
        if (c.pcm == null) continue; // нет аудио-порта: кадры не шлём
        // добираем в аккумулятор сколько есть
        acc_len += c.pcm.?.readPartial(acc[acc_len..]);
        if (acc_len < audio_mod.frame_bytes) continue; // ждём полный кадр
        var box_: [audio_mod.box_bytes]u8 = undefined;
        const frame_seq = c.seq;
        audio_mod.sealFrame(&box_, c.secret, c.call_id, frame_seq, acc[0..]);
        acc_len = 0;
        c.seq = frame_seq + 1;
        _ = app.eng.callAudio(c.cid, frame_seq, &box_) catch {};
    }
}

/// Завершить звонок: остановить поток, закрыть аудио, освободить состояние.
fn endCallLocked(app: *App, why: []const u8) void {
    const c = app.call orelse return;
    app.call = null; // micLoop видит null и выходит без обращений к c
    c.stop_flag.store(true, .release);
    c.up = false;
    if (c.audio_thread) |t| {
        app.unlock();
        t.join();
        app.lock();
    }
    if (c.pcm) |*p| p.deinit();
    app.alloc.destroy(c);
    std.debug.print("\n<< звонок: {s}\n> ", .{why});
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

fn cmdCall(app: *App, args: []const u8) !void {
    const cid = try std.fmt.parseInt(i64, std.mem.trim(u8, args, " "), 10);
    app.lock();
    if (app.call != null) return error.Busy;
    const sess = app.eng.sessions.get(cid) orelse {
        app.unlock();
        return error.NoSession;
    };
    var call_id: [16]u8 = undefined;
    app.io.random(&call_id);
    const c = try app.alloc.create(CallState);
    c.* = .{ .cid = cid, .call_id = call_id, .secret = sess.callSecret(call_id) };
    app.call = c;
    _ = app.eng.callSignal(cid, audio_mod.CallOp.offer, call_id) catch {
        app.alloc.destroy(c);
        app.call = null;
        app.unlock();
        return error.NoSession;
    };
    app.unlock();
    std.debug.print("<< вызываю... (answer после ответа, hangup — отмена)\n> ", .{});
}

fn cmdAnswer(app: *App) !void {
    app.lock();
    defer app.unlock();
    const c = app.call orelse return error.NoCall;
    if (c.up) return;
    _ = app.eng.callSignal(c.cid, audio_mod.CallOp.accept, c.call_id) catch return error.NoSession;
    startCallAudio(app, c);
    std.debug.print("<< линия открыта\n> ", .{});
}

fn cmdHangup(app: *App) !void {
    app.lock();
    defer app.unlock();
    const c = app.call orelse return error.NoCall;
    _ = app.eng.callSignal(c.cid, audio_mod.CallOp.hangup, c.call_id) catch {};
    endCallLocked(app, "вы повесили трубку");
}

// ------------------------------------------------- автоподключение (LAN)
/// Фоновый поток: раз в 2 секунды рассылает анонс (bundle + порт) в
/// мультикаст-группу и слушает чужие. Видит анонс добавленного контакта —
/// сам звонит по TCP. Кто чей bundle меньше — тот инициатор (без дублей).
fn linkerLoop(app: *App) void {
    var disc = discover_mod.Discovery.init() catch return;
    defer disc.deinit();
    std.debug.print("[link] поток запущен\n", .{});
    const my_bundle = app.id.bundle();
    const sleep: std.os.linux.timespec = .{ .sec = 2, .nsec = 0 };
    while (app.running) {
        _ = std.os.linux.nanosleep(&sleep, null);
        disc.announce(my_bundle, app.listen_port);
        var heard: usize = 0;
        while (heard < 8) : (heard += 1) {
            const a = disc.waitAnnounce(300) orelse break;
            if (std.mem.eql(u8, &a.bundle, &my_bundle)) continue;
            const cid = contactIdByBundle(app, a.bundle) orelse continue;
            app.lock();
            const linked = app.eng.sessions.get(cid) != null;
            const blocked = app.eng.contacts.items[@intCast(cid - 1)].blocked;
            app.unlock();
            if (linked or blocked) continue;
            // инициатор — сторона с меньшим bundle (детерминизм, без гонки)
            const i_init = std.mem.order(u8, &my_bundle, &a.bundle) == .lt;
            if (!i_init) continue;
            var ab: [32]u8 = undefined;
            const addr = discover_mod.fmtAddr(&ab, a.ip, a.port);
            establishTo(app, addr, cid, .initiator) catch continue;
            app.lock();
            if (!app.eng.contacts.items[@intCast(cid - 1)].online)
                app.eng.markSeen(cid, app.nowMs());
            app.unlock();
            app.lock();
            if (!app.eng.contacts.items[@intCast(cid - 1)].online)
                app.eng.markSeen(cid, app.nowMs());
            app.unlock();
        }
    }
}

/// Автолистенер: m1 несёт enc_pk звонящего — опознаём контакт и
/// поднимаем responder-сессию establishIdentified. Не-контакты закрываются.
fn identifyCb(ctx: *anyopaque, enc_pk: [32]u8) ?session_mod.Session.IdentifyResult {
    const app: *App = @ptrCast(@alignCast(ctx));
    for (app.eng.contacts.items) |c| {
        if (std.mem.eql(u8, c.bundle[0..32], &enc_pk)) {
            return .{ .sign_pk = c.bundle[32..64].* };
        }
    }
    return null;
}

fn autoAcceptLoop(app: *App, listener: *tcp.Listener) void {
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
        // кадр m1: [len u16][m1 64]
        var hdr: [2]u8 = undefined;
        readRawAll(tc, &hdr) catch {
            tc.deinit();
            continue;
        };
        const m1_len = std.mem.readInt(u16, &hdr, .little);
        if (m1_len != 64) {
            tc.deinit();
            continue;
        }
        var m1: [64]u8 = undefined;
        readRawAll(tc, &m1) catch {
            tc.deinit();
            continue;
        };
        // какой это контакт — узнаем из enc_pk в m1
        var found_cid: i64 = -1;
        {
            app.lock();
            defer app.unlock();
            for (app.eng.contacts.items, 0..) |c, i| {
                if (std.mem.eql(u8, c.bundle[0..32], m1[32..64])) {
                    found_cid = @intCast(i + 1);
                    break;
                }
            }
        }
        if (found_cid < 0) {
            tc.deinit();
            continue;
        }
        var eph: [32]u8 = undefined;
        app.io.random(&eph);
        const sc = app.alloc.create(SessCtx) catch {
            tc.deinit();
            continue;
        };
        sc.* = .{ .app = app, .cid = found_cid };
        const s = session_mod.Session.establishIdentified(
            app.alloc,
            tc.conn(),
            &m1,
            app.id,
            eph,
            identifyCb,
            app,
            app,
            wrapConn,
            .{ .ctx = sc, .onEnvelope = envIn, .onClosed = onClosed },
            app.io,
        ) catch {
            app.alloc.destroy(sc);
            tc.deinit();
            continue;
        } orelse {
            app.alloc.destroy(sc);
            tc.deinit();
            continue;
        };
        app.bindSession(found_cid, s, sc) catch {};
    }
}

fn readRawAll(tc: *tcp.TcpConn, out: []u8) !void {
    var got: usize = 0;
    while (got < out.len) {
        const n = std.posix.read(tc.fd, out[got..]) catch return error.Closed;
        if (n == 0) return error.Closed;
        got += n;
    }
}

// ------------------------------------------------------------- commands
fn cmdInvite(app: *App, args: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, args, " ");
    const name = it.next() orelse "shopot";
    const addr = it.next();
    var out: [256]u8 = undefined;
    const code = try invite_mod.encode(&out, app.id.bundle(), name, addr);
    std.debug.print("{s}\n", .{code});
}

fn cmdAdd(app: *App, args: []const u8) !void {
    const trimmed = std.mem.trim(u8, args, " ");
    if (std.mem.startsWith(u8, trimmed, "shopot1.")) {
        const inv = try invite_mod.decode(trimmed);
        const idx = try app.eng.addContact(inv.name(), inv.bundle);
        const cid: i64 = @intCast(idx + 1);
        try app.hb.put(cid, .{});
        if (app.log) |log| {
            var buf: [97]u8 = undefined;
            buf[0] = @intCast(inv.name().len);
            @memcpy(buf[1 .. 1 + inv.name().len], inv.name());
            @memcpy(buf[1 + inv.name().len .. 1 + inv.name().len + 64], &inv.bundle);
            _ = log.append(.contact, buf[0 .. 1 + inv.name().len + 64]) catch {};
        }
        std.debug.print("контакт {s} = id {d}\n", .{ inv.name(), cid });
        // Если код содержит адрес — подключение происходит сразу, без connect/id.
        if (inv.addr()) |addr| establishTo(app, addr, cid, .initiator) catch |e| {
            std.debug.print("автоподключение: {s}\n", .{@errorName(e)});
        };
        return;
    }
    var it = std.mem.tokenizeAny(u8, trimmed, " ");
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
        const idx = app.eng.addContact(name, bundle) catch return;
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

// ------------------------------------------------------------------ TUI
/// Полноэкранный режим (как у C++-FTXUI, но на голом ANSI): панель
/// контактов сверху, лента сообщений, строка ввода, подсказки клавиш.
fn tuiLoop(app: *App) !void {
    app.tui = true;
    var kb = try tui_mod.Keyboard.init();
    defer kb.deinit();
    tui_mod.enterScreen();
    defer tui_mod.leaveScreen();

    var input: [512]u8 = undefined;
    var input_len: usize = 0;
    var selected: usize = 0; // индекс в контактах
    var scroll: usize = 0; // сколько строк ленты не показываем снизу

    while (app.running) {
        // ---- рендер (полный кадр; терминал 80x24+ — это копейки)
        {
            const sz = tui_mod.termSize();
            var frame: [8192]u8 = undefined;
            var n: usize = 0;
            const wr = struct {
                fn put(buf: []u8, i: *usize, bytes: []const u8) void {
                    if (i.* + bytes.len > buf.len) return;
                    @memcpy(buf[i.* .. i.* + bytes.len], bytes);
                    i.* += bytes.len;
                }
            };
            wr.put(&frame, &n, "\x1b[H\x1b[2J");

            // строка 1: контакты
            {
                var bar: [256]u8 = undefined;
                var bn: usize = 0;
                app.lock();
                for (app.eng.contacts.items, 0..) |c, i| {
                    if (bn >= bar.len - 24) break;
                    const mark: []const u8 = if (i == selected) ">" else " ";
                    const state = if (c.blocked) "!" else if (c.online) "+" else "-";
                    const piece = std.fmt.bufPrint(bar[bn..], "{s}{d}:{s}{s} ", .{ mark, i + 1, c.getName(), state }) catch break;
                    bn += piece.len;
                }
                const call = if (app.call != null) " | ЗВОНОК" else "";
                var head: [320]u8 = undefined;
                const h = std.fmt.bufPrint(&head, "\x1b[1;36mshopot  [{s}]{s}\x1b[0m ", .{ bar[0..bn], call }) catch "";
                wr.put(&frame, &n, h);
                app.unlock();
                wr.put(&frame, &n, "\r\n");
            }

            // строки 2..h-3: лента
            {
                const rows: usize = if (sz.h > 4) sz.h - 4 else 1;
                var shown: usize = 0;
                const idx: usize = app.chat_count;
                // прокрутка: показываем последние (rows - scroll) строк
                var start: usize = 0;
                if (app.chat_count > rows) {
                    start = app.chat_count - rows;
                    if (scroll > 0 and scroll <= start) start -= scroll;
                }
                app.lock();
                while (shown < rows and idx < app.chat_count) {
                    const line_no = start + shown;
                    if (line_no >= app.chat_count) break;
                    const slot = app.chat_lines[(app.chat_head + app.chat_lines.len - app.chat_count + line_no) % app.chat_lines.len];
                    wr.put(&frame, &n, " ");
                    wr.put(&frame, &n, slot.view());
                    wr.put(&frame, &n, "\x1b[K\r\n");
                    shown += 1;
                }
                app.unlock();
                while (shown < rows) : (shown += 1) wr.put(&frame, &n, "\x1b[K\r\n");
            }

            // строка ввода
            {
                wr.put(&frame, &n, "\x1b[32m> ");
                wr.put(&frame, &n, input[0..input_len]);
                wr.put(&frame, &n, "_\x1b[0m\x1b[K\r\n");
            }
            // подсказки
            wr.put(&frame, &n, "\x1b[2menter=отправить · tab=контакт · c=звонок · a=принять · h=положить · b=блок · /команда · q=выход\x1b[0m\x1b[K");
            tui_mod.writeAllRaw(frame[0..n]);
        }

        // ---- ввод
        const key = kb.poll(100);
        switch (key) {
            .none => {},
            .ctrl_c => app.running = false,
            .esc => {
                input_len = 0;
            },
            .enter => {
                if (input_len == 0) {
                    // пустой ввод: показать контакты
                    continue;
                }
                app.lock();
                const n_contacts = app.eng.contacts.items.len;
                app.unlock();
                if (n_contacts == 0) {
                    input_len = 0;
                    continue;
                }
                const cid: i64 = @intCast(selected + 1);
                if (input[0] == '/') {
                    app.lock();
                    var out: [256]u8 = undefined;
                    const t = std.fmt.bufPrint(&out, "self: {s}", .{input[1..input_len]}) catch "";
                    app.unlock();
                    app.pushChat(t);
                    var exec_buf: [512]u8 = undefined;
                    @memcpy(exec_buf[0 .. input_len - 1], input[1..input_len]);
                    const ok = execCmd(app, exec_buf[0 .. input_len - 1]);
                    if (!ok) app.running = false;
                } else {
                    app.lock();
                    app.eng.sendText(cid, input[0..input_len]) catch |e| {
                        var eb: [96]u8 = undefined;
                        const t = std.fmt.bufPrint(&eb, "! ошибка: {s}", .{@errorName(e)}) catch "";
                        app.pushChat(t);
                    };
                    app.unlock();
                    var mine: [300]u8 = undefined;
                    app.lock();
                    const name = if (selected < app.eng.contacts.items.len) app.eng.contacts.items[selected].getName() else "?";
                    app.unlock();
                    const t = std.fmt.bufPrint(&mine, ">> {s}: {s}", .{ name, input[0..input_len] }) catch "";
                    app.pushChat(t);
                }
                input_len = 0;
                scroll = 0;
            },
            .tab => {
                app.lock();
                const nc = app.eng.contacts.items.len;
                app.unlock();
                if (nc > 0) selected = (selected + 1) % nc;
            },
            .up => {
                if (scroll < app.chat_count) scroll += 1;
            },
            .down => {
                if (scroll > 0) scroll -= 1;
            },
            .backspace => {
                if (input_len > 0) {
                    // удалить последний кодпоинт utf-8
                    input_len -= 1;
                    while (input_len > 0 and (input[input_len] & 0xC0) == 0x80) input_len -= 1;
                }
            },
            .char => |ch| {
                // при пустом вводе латинские буквы — горячие клавиши
                if (input_len == 0 and ch.len == 1) {
                    switch (ch[0]) {
                        'q' => {
                            app.running = false;
                            return;
                        },
                        'c' => {
                            app.lock();
                            const nc = app.eng.contacts.items.len;
                            app.unlock();
                            if (nc > 0) {
                                var cb: [16]u8 = undefined;
                                const cid_str = std.fmt.bufPrint(&cb, "{d}", .{selected + 1}) catch continue;
                                cmdCall(app, cid_str) catch |e| {
                                    var eb: [96]u8 = undefined;
                                    const t = std.fmt.bufPrint(&eb, "! звонок: {s}", .{@errorName(e)}) catch "";
                                    app.pushChat(t);
                                };
                            }
                            continue;
                        },
                        'a' => {
                            cmdAnswer(app) catch |e| {
                                var eb: [96]u8 = undefined;
                                const t = std.fmt.bufPrint(&eb, "! звонок: {s}", .{@errorName(e)}) catch "";
                                app.pushChat(t);
                            };
                            continue;
                        },
                        'h' => {
                            cmdHangup(app) catch {};
                            continue;
                        },
                        'b' => {
                            app.lock();
                            const nc = app.eng.contacts.items.len;
                            const blocked = if (nc > 0) app.eng.contacts.items[selected].blocked else false;
                            app.unlock();
                            if (nc > 0) {
                                var cb: [16]u8 = undefined;
                                const cid_str = std.fmt.bufPrint(&cb, "{d}", .{selected + 1}) catch continue;
                                cmdBlock(app, cid_str, !blocked) catch {};
                            }
                            continue;
                        },
                        else => {},
                    }
                }
                if (input_len + ch.len <= input.len) {
                    @memcpy(input[input_len .. input_len + ch.len], ch);
                    input_len += ch.len;
                    scroll = 0;
                }
            },
            .unknown => {},
        }
    }
}

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
        if (!execCmd(app, trimmed)) break;
    }
}

/// Исполнение команды REPL/TUI (возвращает false для выхода).
fn execCmd(app: *App, trimmed: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, trimmed, " ");
    const cmd = it.next() orelse return true;
    const rest = std.mem.trim(u8, trimmed[cmd.len..], " ");

    if (std.mem.eql(u8, cmd, "quit") or std.mem.eql(u8, cmd, "q")) {
        app.running = false;
    } else if (std.mem.eql(u8, cmd, "contacts")) {
        cmdContacts(app);
    } else if (std.mem.eql(u8, cmd, "invite")) {
        cmdInvite(app, rest) catch |e| std.debug.print("ошибка: {s}\n", .{@errorName(e)});
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
    } else if (std.mem.eql(u8, cmd, "call")) {
        cmdCall(app, rest) catch |e| std.debug.print("ошибка: {s}\n", .{@errorName(e)});
    } else if (std.mem.eql(u8, cmd, "answer")) {
        cmdAnswer(app) catch |e| std.debug.print("ошибка: {s}\n", .{@errorName(e)});
    } else if (std.mem.eql(u8, cmd, "hangup")) {
        cmdHangup(app) catch |e| std.debug.print("ошибка: {s}\n", .{@errorName(e)});
    } else if (std.mem.eql(u8, cmd, "connect")) {
        var ait = std.mem.tokenizeAny(u8, rest, " ");
        const addr = ait.next() orelse return true;
        const cid = std.fmt.parseInt(i64, ait.next() orelse return true, 10) catch return true;
        establishTo(app, addr, cid, .initiator) catch |e|
            std.debug.print("ошибка: {s}\n", .{@errorName(e)});
    } else if (std.mem.eql(u8, cmd, "listen")) {
        var ait = std.mem.tokenizeAny(u8, rest, " ");
        const addr = ait.next() orelse return true;
        const cid = std.fmt.parseInt(i64, ait.next() orelse return true, 10) catch return true;
        const lsn = tcp.listen(addr) catch |e| {
            std.debug.print("ошибка listen: {s}\n", .{@errorName(e)});
            return true;
        };
        const lp = app.alloc.create(tcp.Listener) catch return true;
        lp.* = lsn;
        const th = std.Thread.spawn(.{}, struct {
            fn go(a: *App, l: *tcp.Listener, c: i64) void {
                acceptLoop(a, l, c);
            }
        }.go, .{ app, lp, cid }) catch return true;
        th.detach();
        std.debug.print("слушаю {s} для id {d}\n", .{ addr, cid });
    } else {
        std.debug.print("не знаю команду. команды:\n{s}\n", .{usage});
    }
    return true;
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

        var pcm_buf: [512]u8 = undefined;
        const pcm_dir = try std.fmt.bufPrint(&pcm_buf, "{s}/.shopot/pcm", .{home});
        std.Io.Dir.createDirAbsolute(io, pcm_dir, .default_dir) catch {};
        var pcm_heap: []const u8 = "";
        if (home.len > 0) {
            pcm_heap = std.fmt.allocPrint(alloc, "{s}/.shopot/pcm", .{home}) catch "";
        }

        var app = App{
            .alloc = alloc,
            .io = io,
            .id = &id,
            .eng = &eng,
            .log = log_ptr,
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *SessCtx).init(alloc),
            .call_pcm_dir = if (pcm_heap.len > 0) pcm_heap else null,
        };
        eng.ev = app.events();

        loadContacts(&app);

        const th = std.Thread.spawn(.{}, tickerLoop, .{&app}) catch return error.OutOfMemory;
        th.detach();

        // автолистенер: любой контакт из списка может подключиться сам
        var lsn: ?tcp.Listener = null;
        var listen_port: u16 = 7777;
        {
            var attempt: u16 = 7777;
            while (attempt < 7787) : (attempt += 1) {
                var pbuf: [24]u8 = undefined;
                const a = std.fmt.bufPrint(&pbuf, "0.0.0.0:{d}", .{attempt}) catch unreachable;
                if (tcp.listen(a)) |l| {
                    lsn = l;
                    listen_port = attempt;
                    break;
                } else |_| {}
            }
            if (lsn) |l| {
                app.listen_port = listen_port;
                const lp = app.alloc.create(tcp.Listener) catch return error.OutOfMemory;
                lp.* = l;
                const lt = std.Thread.spawn(.{}, autoAcceptLoop, .{ &app, lp }) catch return error.OutOfMemory;
                lt.detach();
                const linker = std.Thread.spawn(.{}, linkerLoop, .{&app}) catch return error.OutOfMemory;
                linker.detach();
                std.debug.print("авто-режим: слушаю 0.0.0.0:{d}, LAN-поиск включён\n", .{listen_port});
            } else {
                std.debug.print("авто-режим: порты 7777-7786 заняты, LAN-поиск выключен\n", .{});
            }
        }

        // интерактивный терминал — полноэкранный TUI; иначе — построчный REPL
        const is_tty = blk: {
            _ = std.posix.tcgetattr(0) catch break :blk false;
            break :blk true;
        };
        if (is_tty) {
            try tuiLoop(&app);
        } else {
            try repl(&app);
        }

        eng.deinit();
        return;
    }

    std.debug.print("{s}\n", .{usage});
}
