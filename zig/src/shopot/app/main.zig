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
const cli_srv = @import("cli_server.zig");
const cli_mod = cli_srv;

const usage =
    \\shopot-zig — шифрованный мессенджер (std-only Zig)
    \\
    \\  init                        создать личность (~/.shopot/zig-seed, 0600)
    \\  id                          показать bundle и отпечаток
    \\  invite [имя] [addr]         односторонний код: держатель делает add
    \\  add <код|bundle-hex> [имя]  добавить контакт (код — одной командой)
    \\  chat                        интерактивный мессенджер (TUI) + CLI-апи
    \\  serve                       демон без локального ввода (только CLI-апи:
    \\                              UDS ~/.shopot/api.sock)
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
    start_ms: i64 = 0, // для таймера длительности
    seq: u32 = 0,
    /// Гудки/разговор. Установлено после accept.
    up: bool = false,
    pcm: ?audio_mod.PcmPort = null,
    audio_thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

// ------------------------------------------------------------------ app
pub const App = struct {
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
    // переписки по контактам (TUI): threads[cid-1], heap-массив
    threads: []tui_mod.Thread = &.{},
    sel: usize = 0, // выбранный чат (индекс контакта)
    tz: i32 = 0, // смещение локальной TZ, сек
    tui: bool = false,
    // ---- CLI-сервер (UDS-апи) ----
    cli: ?*cli_srv.Server = null, // сервер (включён, когда != null)
    cli_out: ?*cli_srv.Conn = null, // кому fb отдаёт ответы команд (под cli_mu)
    cli_mu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false), // приёмник fb-ответов

    // ---- Односторонние инвайты (v2) ----
    /// Выданные приглашения: секрет ждёт предъявителя JOIN-конвертом.
    invites: [4]InviteReg = @splat(.{}),
    /// JOIN-данные по cid: отправить первым конвертом после рукопожатия.
    join_map: std.AutoHashMapUnmanaged(i64, JoinInfo) = .empty,

    running: bool = true,

    /// Спин-блок: держится микросекунды (append в список), потоков мало.
    pub fn lock(self: *App) void {
        while (self.mu.swap(true, .acquire)) std.Thread.yield() catch {};
    }
    pub fn unlock(self: *App) void {
        self.mu.store(false, .release);
    }

    /// Спин-лок cli_mu — приёмника ответов fb (тот же паттерн, что у mu).
    pub fn cliLock(self: *App) void {
        while (self.cli_mu.swap(true, .acquire)) std.Thread.yield() catch {};
    }
    pub fn cliUnlock(self: *App) void {
        self.cli_mu.store(false, .release);
    }

    /// Время — прямой syscall: НЕ трогаем io, чтобы не конкурировать
    /// с сетевыми операциями из других потоков (Threaded io).
    fn nowMs(self: *App) i64 {
        _ = self;
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.REALTIME, &ts);
        return @as(i64, @intCast(ts.sec)) * 1000 + @as(i64, @intCast(@divTrunc(ts.nsec, std.time.ns_per_ms)));
    }

    /// Добавить строку переписки контакта idx (ВЫЗЫВАТЬ ПОД локом).
    fn msgLineLocked(self: *App, idx: usize, kind: tui_mod.Kind, name: []const u8, txt: []const u8) void {
        if (idx >= self.threads.len) return;
        self.threads[idx].push(self.nowMs(), kind, name, txt);
        if (idx != self.sel) self.threads[idx].unread += 1;
    }

    /// Служебная строка в чат контакта idx (ВЫЗЫВАТЬ ПОД локом).
    fn sysLineLocked(self: *App, idx: ?usize, txt: []const u8) void {
        const i = idx orelse self.sel;
        if (i >= self.threads.len) return;
        self.threads[i].push(self.nowMs(), .sys, "", txt);
        if (i != self.sel) self.threads[i].unread += 1;
    }

    /// Привязать сессию к контакту. sc — контекст событий, уже создан и
    /// используется rx-потоком сессии, поэтому здесь не уничтожается никогда
    /// (короткоживущий процесс, счёт контекстов равен числу сессий).
    fn bindSession(self: *App, cid: i64, s: *session_mod.Session, sc: *SessCtx) !void {
        self.lock();
        defer self.unlock();
        return self.bindSessionLocked(cid, s, sc);
    }

    /// bind без взятия лока — вызывать ПОД self.mu.
    fn bindSessionLocked(self: *App, cid: i64, s: *session_mod.Session, sc: *SessCtx) !void {
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
        // сессия поднята — слить outbox (доставка офлайн-хвоста)
        self.eng.flushOutbox(cid);
    }

    fn events(self: *App) engine_mod.Events {
        return .{ .ctx = self, .onText = onTextEv, .onReaction = onReactionEv, .onPresence = onPresenceEv, .onBlockedNotice = onBlockedEv, .onCallSignal = onCallSignalEv, .onCallAudio = onCallAudioEv, .onDelivered = onDeliveredEv };
    }
};

/// Выданное одностороннее приглашение (реестр в App.invites).
const InviteReg = struct {
    secret: [invite_mod.secret_len]u8 = @splat(0),
    created_ms: i64 = 0,
    /// true — код уже redeemed (секрет погашен).
    used: bool = false,
};

/// JOIN-данные, которые отправим после установления сессии.
const JoinInfo = struct {
    secret: [invite_mod.secret_len]u8 = @splat(0),
    /// Моё имя — его увидит приглашающий.
    name_buf: [32]u8 = @splat(0),
    name_len: u8 = 0,

    fn name(self: *const JoinInfo) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

const SessCtx = struct {
    app: *App,
    cid: i64,
    /// Сессия pending-join (cid == -1): связка для промоушена после JOIN.
    s: ?*session_mod.Session = null,
};

fn envIn(ctx: *anyopaque, env: envelope.Envelope) void {
    const sc: *SessCtx = @ptrCast(@alignCast(ctx));
    const app = sc.app;
    if (sc.cid == -1) {
        // pending-join: единственный допустимый конверт — JOIN
        handleJoinEnvelope(sc, env);
        return;
    }
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

/// JOIN на pending-сессии (sc.cid == -1): подпись привязывает bundle
/// заявителя к транскрипту (ключам сессии), HMAC доказывает держателя
/// инвайт-кода. Валидно — контакт добавляется, сессия биндится.
fn handleJoinEnvelope(sc: *SessCtx, env: envelope.Envelope) void {
    const app = sc.app;
    const sess = sc.s orelse return;
    const j = switch (env) {
        .join => |j| j,
        else => {
            sess.close();
            return;
        },
    };
    const transcript = sess.keys.transcript;
    // 1) подпись: bundle заявителя привязан к ключам этой сессии
    identity.Identity.verify(j.bundle[32..64].*, &transcript, j.sig) catch {
        sess.close();
        return;
    };
    var failed = false;
    var cid: i64 = 0;
    {
        app.lock();
        defer app.unlock();
        if (sc.cid != -1) return; // уже промоутнут (повторный кадр)
        // 2) HMAC: секрет одного из живых (не погашенных) приглашений
        var matched: ?usize = null;
        for (&app.invites, 0..) |*reg, i| {
            if (reg.used) continue;
            var mac: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &transcript, &reg.secret);
            if (std.mem.eql(u8, &mac, &j.hmac)) {
                matched = i;
                break;
            }
        }
        if (matched == null) {
            failed = true;
        } else {
            app.invites[matched.?].used = true;
            if (contactIdByBundle(app, j.bundle)) |existing| {
                cid = existing; // переподключение держателем кода
            } else {
                const ni = app.eng.addContact(j.name, j.bundle) catch {
                    failed = true;
                    return;
                };
                cid = @intCast(ni + 1);
                app.hb.put(cid, .{}) catch {};
                // контакт переживает рестарт: пишем в шифрованный лог
                if (app.log) |log| logContact(app, log, j.name, j.bundle, null);
            }
            if (!failed) {
                sc.cid = cid;
                app.bindSessionLocked(cid, sess, sc) catch {
                    failed = true;
                };
            }
        }
    }
    if (failed) {
        sess.close();
        return;
    }
    var msg: [96]u8 = undefined;
    app.lock();
    defer app.unlock();
    const line = std.fmt.bufPrint(&msg, "контакт {s} подключился по инвайту (id {d})", .{ app.eng.contacts.items[@intCast(cid - 1)].getName(), cid }) catch return;
    if (app.tui) {
        app.sysLineLocked(@intCast(cid - 1), line);
    } else {
        std.debug.print("\n<< {s}\n> ", .{line});
    }
    cli_srv.fanoutSysLocked(app, cid, "", line);
    cli_srv.fanoutPresenceLocked(app, cid, "", true);
}

fn onClosed(ctx: *anyopaque) void {
    _ = ctx;
}

/// Индекс контакта по указателю (события движка отдают *const Contact).
fn contactIndexOf(app: *App, from: *const engine_mod.Contact) ?usize {
    for (app.eng.contacts.items, 0..) |*it, i| {
        if (@intFromPtr(it) == @intFromPtr(from)) return i;
    }
    return null;
}

fn onTextEv(ctx: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8, _: i64, body: []const u8) void {
    var hex_buf: [32]u8 = undefined;
    var hx: []const u8 = "?";
    _ = toHex(&hex_buf, &msg_id) catch {};
    hx = hex_buf[0..];
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    if (app.tui) {
        app.msgLineLocked(idx, .theirs, from.getName(), body);
    } else {
        std.debug.print("\n<< [{s}] {s}  (msg {s})\n> ", .{ from.getName(), body, hx });
    }
    cli_srv.fanoutMsgLocked(app, @intCast(idx + 1), from.getName(), body);
}

/// ACK дошёл: сообщение доставлено на устройство пир-а.
fn onDeliveredEv(ctx: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    var hex_buf: [32]u8 = undefined;
    const hx = toHex(&hex_buf, &msg_id) catch return;
    var line: [64]u8 = undefined;
    const t = std.fmt.bufPrint(&line, "доставлено: {s}", .{hx}) catch return;
    if (app.tui) {
        app.sysLineLocked(idx, t);
    } else {
        std.debug.print("\n<< {s}\n> ", .{t});
    }
    const cid: i64 = @intCast(idx + 1);
    persistOutboxAck(app, cid, msg_id);
    cli_srv.fanoutSysLocked(app, cid, from.getName(), t);
}

fn onReactionEv(ctx: *anyopaque, from: *const engine_mod.Contact, r: engine_mod.Reaction) void {
    var hex_buf: [32]u8 = undefined;
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    var line: [128]u8 = undefined;
    const t = std.fmt.bufPrint(&line, "реакция {d} на {s}", .{ r.code, toHex(&hex_buf, &r.msg_id) catch "?" }) catch return;
    if (app.tui) {
        app.sysLineLocked(idx, t);
    } else {
        std.debug.print("\n<< [{s}] {s}\n> ", .{ from.getName(), t });
    }
    cli_srv.fanoutSysLocked(app, @intCast(idx + 1), from.getName(), t);
}

fn onPresenceEv(ctx: *anyopaque, from: *const engine_mod.Contact, online: bool, _: i64) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    if (app.tui) {
        app.sysLineLocked(idx, if (online) "• online" else "• offline");
    } else {
        std.debug.print("\n<< [{s}] {s}\n> ", .{ from.getName(), if (online) "online" else "offline" });
    }
    cli_srv.fanoutPresenceLocked(app, @intCast(idx + 1), from.getName(), online);
}

fn onBlockedEv(ctx: *anyopaque, from: *const engine_mod.Contact) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    std.debug.print("\n<< [{s}] заблокировал вас\n> ", .{from.getName()});
    cli_srv.fanoutSysLocked(app, @intCast(idx + 1), from.getName(), "заблокировал вас");
}

// ------------------------------------------------------------- звонки
/// Входящий сигнал: offer — гудки, accept — линия вверх, reject/hangup — конец.
fn onCallSignalEv(ctx: *anyopaque, from: *const engine_mod.Contact, op: u8, call_id: [16]u8) void {
    // ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn) — второго захвата быть не должно.
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from);
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
            if (app.tui) {
                var line: [128]u8 = undefined;
                const t = std.fmt.bufPrint(&line, "входящий звонок — a: принять, h: отклонить", .{}) catch return;
                app.sysLineLocked(idx, t);
            } else {
                std.debug.print("\n<< входящий звонок от {s}: answer {d} — принять, hangup — отклонить\n> ", .{ from.getName(), cid });
            }
            cli_srv.fanoutSysLocked(app, cid, from.getName(), "входящий звонок — answer принять, hangup отклонить");
        },
        audio_mod.CallOp.accept => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            startCallAudio(app, c);
            if (app.tui) {
                var line: [96]u8 = undefined;
                const t = std.fmt.bufPrint(&line, "линия открыта", .{}) catch return;
                app.sysLineLocked(idx, t);
            } else {
                std.debug.print("\n<< {s} ответил, линия открыта\n> ", .{from.getName()});
            }
            cli_srv.fanoutSysLocked(app, c.cid, from.getName(), "линия открыта");
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
    if (app.tui) {
        app.sysLineLocked(@intCast(c.cid - 1), "звук: aplay < ~/.shopot/pcm/spk · arecord > ~/.shopot/pcm/mic");
    }
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
        // seq u32 в кадре CALL_AUDIO: на максимуме ключ/nonce кадра начали бы
        // повторяться — обрываем звонок раньше (практически недостижимо: ~99 суток)
        if (frame_seq == std.math.maxInt(u32)) {
            endCallLocked(app, "достигнут предел длины звонка");
            continue;
        }
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
    const cid = c.cid;
    app.alloc.destroy(c);
    if (app.tui) {
        app.sysLineLocked(@intCast(cid - 1), why);
    } else {
        std.debug.print("\n<< звонок: {s}\n> ", .{why});
    }
    const cname = if (app.eng.contacts.items.len >= @as(usize, @intCast(cid)))
        app.eng.contacts.items[@intCast(cid - 1)].getName()
    else
        "?";
    cli_srv.fanoutSysLocked(app, cid, cname, why);
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
    c.* = .{ .cid = cid, .call_id = call_id, .secret = sess.callSecret(call_id), .start_ms = app.nowMs() };
    app.call = c;
    _ = app.eng.callSignal(cid, audio_mod.CallOp.offer, call_id) catch {
        app.alloc.destroy(c);
        app.call = null;
        app.unlock();
        return error.NoSession;
    };
    app.unlock();
    if (app.tui) {
        app.lock();
        app.sysLineLocked(@intCast(cid - 1), "вызываю... (h — отмена)");
        app.unlock();
    } else {
        std.debug.print("<< вызываю... (answer после ответа, hangup — отмена)\n> ", .{});
    }
}

fn cmdAnswer(app: *App) !void {
    app.lock();
    defer app.unlock();
    const c = app.call orelse return error.NoCall;
    if (c.up) return;
    if (c.start_ms == 0) c.start_ms = app.nowMs();
    _ = app.eng.callSignal(c.cid, audio_mod.CallOp.accept, c.call_id) catch return error.NoSession;
    startCallAudio(app, c);
    if (app.tui) {
        app.sysLineLocked(@intCast(c.cid - 1), "линия открыта");
    } else {
        std.debug.print("<< линия открыта\n> ", .{});
    }
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
/// IPv4 в строку (без порта).
fn fmtIpBuf(buf: *[16]u8, ip: [4]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?";
}

/// Автодозвон офлайн-контактов по сохранённым адресам: backoff 1с -> 60с
/// с джиттером. Пир в LAN — сработает и анонс (linkerLoop); автодозвон
/// покрывает сети без мультикаста и перезагрузки демона.
fn autodialLoop(app: *App) void {
    var next_try = std.AutoHashMapUnmanaged(i64, i64).empty;
    defer next_try.deinit(app.alloc);
    var attempts = std.AutoHashMapUnmanaged(i64, u32).empty;
    defer attempts.deinit(app.alloc);
    const sleep1: std.os.linux.timespec = .{ .sec = 1, .nsec = 0 };
    while (app.running) {
        _ = std.os.linux.nanosleep(&sleep1, null);
        const now = app.nowMs();
        // кого звонить: офлайн, есть адрес, время пришло
        var dial_cid: i64 = -1;
        var ab: [80]u8 = undefined;
        var addr_copy: [80]u8 = undefined;
        var addr_len: usize = 0;
        {
            app.lock();
            defer app.unlock();
            for (app.eng.contacts.items, 0..) |*c, i| {
                const cid: i64 = @intCast(i + 1);
                if (app.eng.sessions.get(cid) != null or c.blocked) {
                    _ = attempts.remove(cid);
                    continue;
                }
                const a = c.addr(&ab) orelse continue;
                const nt = next_try.get(cid) orelse 0;
                if (nt > now) continue;
                dial_cid = cid;
                addr_len = a.len;
                @memcpy(addr_copy[0..a.len], a);
                break;
            }
        }
        if (dial_cid >= 0) {
            establishTo(app, addr_copy[0..addr_len], dial_cid, .initiator) catch {};
            // backoff: 1s,2s,4s,8s,16s,32s -> потолок 60s (+ джиттер до 50%)
            app.lock();
            defer app.unlock();
            const at = (attempts.get(dial_cid) orelse 0) + 1;
            attempts.put(app.alloc, dial_cid, at) catch {};
            const shift: u6 = @intCast(@min(at, 6));
            const base: i64 = @as(i64, 1000) << shift;
            const capped: i64 = @min(base, 60_000);
            const jitter: i64 = @mod(now, @divTrunc(capped, 2) + 1);
            next_try.put(app.alloc, dial_cid, now + capped + jitter) catch {};
        }
    }
}

fn linkerLoop(app: *App) void {
    var disc = discover_mod.Discovery.init() catch return;
    defer disc.deinit();
    const my_bundle = app.id.bundle();
    const sleep: std.os.linux.timespec = .{ .sec = 2, .nsec = 0 };
    while (app.running) {
        // анонс ПЕРВЫМ делом итерации: старт демона = immediate-анонс,
        // пир с pending-outbox узнаёт о нас за ~RTT, а не через цикл сна
        disc.announce(my_bundle, app.listen_port);
        var heard: usize = 0;
        while (heard < 8) : (heard += 1) {
            const a = disc.waitAnnounce(300) orelse break;
            if (std.mem.eql(u8, &a.bundle, &my_bundle)) continue;
            const cid = contactIdByBundle(app, a.bundle) orelse continue;
            app.lock();
            const linked = app.eng.sessions.get(cid) != null;
            const blocked = app.eng.contacts.items[@intCast(cid - 1)].blocked;
            const join_due = app.join_map.contains(cid);
            app.unlock();
            if (linked or blocked) continue;
            // адрес анонса — сохранить для автодозвона (последний известный)
            {
                var ab_ip: [16]u8 = undefined;
                const c = &app.eng.contacts.items[@intCast(cid - 1)];
                c.setAddr(fmtIpBuf(&ab_ip, a.ip), a.port);
            }
            // инициатор — сторона с меньшим bundle (детерминизм, без гонки);
            // держатель инвайт-кода инициирует ВСЕГДА: приглашающий его не знает
            const i_init = std.mem.order(u8, &my_bundle, &a.bundle) == .lt;
            if (!i_init and !join_due) continue;
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
        _ = std.os.linux.nanosleep(&sleep, null);
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

/// Окно pending-join: 3 с на валидный JOIN, иначе сессия закрывается.
fn joinTimeoutWatch(sc: *SessCtx) void {
    const sleep3: std.os.linux.timespec = .{ .sec = 3, .nsec = 0 };
    _ = std.os.linux.nanosleep(&sleep3, null);
    const app = sc.app;
    app.lock();
    const still_pending = sc.cid == -1;
    app.unlock();
    if (still_pending) {
        if (sc.s) |sp| sp.close();
    }
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
            // держатель инвайт-кода: поднимаем pending-сессию без опознания
            app.lock();
            const has_invite = blk: {
                for (&app.invites) |*reg| {
                    if (!reg.used and reg.created_ms != 0) break :blk true;
                }
                break :blk false;
            };
            app.unlock();
            if (has_invite) {
                var eph2: [32]u8 = undefined;
                app.io.random(&eph2);
                const sc = app.alloc.create(SessCtx) catch {
                    tc.deinit();
                    continue;
                };
                sc.* = .{ .app = app, .cid = -1, .s = null };
                const sp = session_mod.Session.establishPending(
                    app.alloc,
                    tc.conn(),
                    &m1,
                    app.id,
                    eph2,
                    app,
                    wrapConn,
                    .{ .ctx = sc, .onEnvelope = envIn, .onClosed = onClosed },
                    app.io,
                ) catch {
                    app.alloc.destroy(sc);
                    tc.deinit();
                    continue;
                };
                sc.s = sp;
                // окно 3 с: нет валидного JOIN — закрыть
                const tt = std.Thread.spawn(.{}, joinTimeoutWatch, .{sc}) catch {
                    sp.close();
                    app.alloc.destroy(sc);
                    tc.deinit();
                    continue;
                };
                tt.detach();
            } else {
                tc.deinit();
            }
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
    // односторонний v2-код: держатель добавляется ONE add-ом
    var secret: [invite_mod.secret_len]u8 = undefined;
    app.io.random(&secret);
    {
        app.lock();
        defer app.unlock();
        var slot: ?usize = null;
        for (&app.invites, 0..) |*reg, i| {
            if (reg.used or reg.created_ms == 0) {
                slot = i;
                break;
            }
        }
        const i = slot orelse return error.TooManyInvites;
        app.invites[i] = .{ .secret = secret, .created_ms = app.nowMs(), .used = false };
    }
    var out: [256]u8 = undefined;
    const code = try invite_mod.encode2(&out, app.id.bundle(), secret, name, addr);
    fb(app, null, code);
    fb(app, null, "односторонний код: отдай его — держатель сделает add, больше ничего не нужно");
}

fn cmdAdd(app: *App, args: []const u8) !void {
    var trimmed = std.mem.trim(u8, args, " ");
    var name: []const u8 = "";
    var bundle: [64]u8 = undefined;
    var addr_buf: [80]u8 = undefined;
    var addr: ?[]const u8 = null;
    // моё имя для JOIN (видит приглашающий): хвост после кода
    var my_name: []const u8 = "друг";
    var join_after: ?JoinInfo = null;
    if (std.mem.indexOfScalar(u8, trimmed, ' ')) |sp| {
        if (std.mem.startsWith(u8, trimmed, invite_mod.v2_prefix)) {
            my_name = std.mem.trim(u8, trimmed[sp + 1 ..], " ");
            if (my_name.len == 0 or my_name.len > 32) return error.BadArgs;
            trimmed = trimmed[0..sp];
        }
    }
    if (std.mem.startsWith(u8, trimmed, invite_mod.v2_prefix) or std.mem.startsWith(u8, trimmed, "shopot1.")) {
        const inv = try invite_mod.decode(trimmed);
        name = inv.name();
        bundle = inv.bundle;
        // inv.addr() — только хост: порт живёт отдельно, собираем "host:port"
        if (inv.host_len > 0) {
            addr = std.fmt.bufPrint(&addr_buf, "{s}:{d}", .{ inv.addr().?, inv.port }) catch return error.BadArgs;
        }
        // v2: держатель кода — JOIN первым конвертом после рукопожатия
        if (inv.v2) join_after = .{
            .secret = inv.secret,
            .name_len = @intCast(my_name.len),
            .name_buf = blk: {
                var nb: [32]u8 = @splat(0);
                @memcpy(nb[0..my_name.len], my_name);
                break :blk nb;
            },
        };
    } else {
        var it = std.mem.tokenizeAny(u8, trimmed, " ");
        name = it.next() orelse return error.BadArgs;
        const hex = it.next() orelse return error.BadArgs;
        bundle = try parseHex64(hex);
    }
    // мутации движка/хешмапы — строго под локом (ticker и рендер итерируют)
    var cid: i64 = 0;
    {
        app.lock();
        defer app.unlock();
        const idx = try app.eng.addContact(name, bundle);
        cid = @intCast(idx + 1);
        try app.hb.put(cid, .{});
        if (addr) |a| saveContactAddr(app, cid, a);
        if (app.log) |log| {
            logContact(app, log, name, bundle, addr);
        }
    }
    var msg: [96]u8 = undefined;
    const t = std.fmt.bufPrint(&msg, "контакт {s} = id {d}", .{ name, cid }) catch "контакт добавлен";
    fb(app, @intCast(cid - 1), t);
    // v2: запомнить JOIN-данные — отправим первым конвертом после рукопожатия
    if (join_after) |ji| {
        app.join_map.put(app.alloc, cid, ji) catch {};
    }
    // Если код содержит адрес — подключение происходит сразу, без connect/id.
    // Без адреса — LAN-захват: linkerLoop дозвонится до анонса приглашающего.
    if (addr) |a| establishTo(app, a, cid, .initiator) catch |e| {
        var eb: [64]u8 = undefined;
        const et = std.fmt.bufPrint(&eb, "автоподключение: {s}", .{@errorName(e)}) catch "!";
        fb(app, @intCast(cid - 1), et);
    };
}

fn cmdContacts(app: *App) void {
    var lines_buf: [16][128]u8 = undefined;
    var lens: [16]usize = @splat(0);
    var n: usize = 0;
    {
        app.lock();
        defer app.unlock();
        const now = app.nowMs();
        for (app.eng.contacts.items, 0..) |c, i| {
            if (n >= lines_buf.len) break;
            const cid: i64 = @intCast(i + 1);
            const seen: ?i64 = app.eng.lastSeen(cid);
            const ago = if (seen) |sv| now - sv else -1;
            var q: usize = 0;
            for (app.eng.outbox.items) |*e| {
                if (e.cid == cid) q += 1;
            }
            const t = std.fmt.bufPrint(&lines_buf[n], "id {d}: {s} {s}{s} (last seen: {d} мс назад){s}", .{
                cid,
                c.getName(),
                if (c.online) "[online]" else "[offline]",
                if (c.blocked) " [BLOCKED]" else "",
                ago,
                if (q > 0) " [в очереди]" else "",
            }) catch continue;
            lens[n] = t.len;
            n += 1;
        }
    }
    if (n == 0) {
        fb(app, null, "нет контактов");
        return;
    }
    for (lines_buf[0..n], lens[0..n]) |*line, l| {
        fb(app, null, line[0..l]);
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
    // держатель инвайта: первым конвертом — JOIN (подаётся ДО любого текста)
    sendJoinIfDue(app, cid, s);
}

/// Отправка JOIN по join_map (после установления сессии, без app.mu).
fn sendJoinIfDue(app: *App, cid: i64, s: *session_mod.Session) void {
    const ji = app.join_map.get(cid) orelse return;
    _ = app.join_map.remove(cid);
    const transcript = s.keys.transcript;
    var sig: [64]u8 = undefined;
    app.id.sign(&transcript, &sig) catch return;
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &transcript, &ji.secret);
    const j = envelope.Join{
        .bundle = app.id.bundle(),
        .name = ji.name(),
        .sig = sig,
        .hmac = mac,
    };
    s.sendEnvelope(.{ .join = j }) catch {};
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
            fb(app, null, "рукопожатие не удалось");
            continue;
        };
        app.bindSession(cid, s, sc) catch {};
        var sm: [64]u8 = undefined;
        const st = std.fmt.bufPrint(&sm, "сессия установлена", .{}) catch "сессия";
        fb(app, @intCast(idx), st);
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
    const r = try app.eng.sendText(cid, body);
    if (r == .queued) {
        persistOutboxAdd(app);
        var qb: [80]u8 = undefined;
        const t = std.fmt.bufPrint(&qb, "в очереди: доставлю, когда {s} появится", .{app.eng.contacts.items[@intCast(cid - 1)].getName()}) catch "в очереди";
        fb(app, @intCast(cid - 1), t);
    }
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

/// Записать контакт в лог (с адресом, если известен).
fn logContact(app: *App, log: *store_mod.Log, name: []const u8, bundle: [64]u8, addr_: ?[]const u8) void {
    const a: []const u8 = addr_ orelse "";
    var buf: [64 + 1 + 32 + 1 + 64 + 2]u8 = undefined;
    var n: usize = 0;
    buf[0] = @intCast(name.len);
    n = 1;
    @memcpy(buf[n .. n + name.len], name);
    n += name.len;
    @memcpy(buf[n .. n + 64], &bundle);
    n += 64;
    // хвост адреса: [alen][host][port u16 LE] (для совместимости со старыми логами)
    const host_port = splitHostPort(a);
    const alen = host_port.host.len;
    if (alen > 0 and alen <= 64) {
        buf[n] = @intCast(alen);
        n += 1;
        @memcpy(buf[n .. n + alen], host_port.host);
        n += alen;
        std.mem.writeInt(u16, buf[n..][0..2], host_port.port, .little);
        n += 2;
    }
    _ = log.append(.contact, buf[0..n]) catch {};
    _ = app;
}

const HostPort = struct { host: []const u8, port: u16 };

/// "host:port" -> {host, port}; без порта — port 0.
fn splitHostPort(a: []const u8) HostPort {
    if (std.mem.lastIndexOfScalar(u8, a, ':')) |c| {
        const port = std.fmt.parseInt(u16, a[c + 1 ..], 10) catch 0;
        return .{ .host = a[0..c], .port = port };
    }
    return .{ .host = a, .port = 0 };
}

/// Запомнить адрес контакта (в памяти и логе).
fn saveContactAddr(app: *App, cid: i64, host_port_str: []const u8) void {
    const hp = splitHostPort(host_port_str);
    const c = &app.eng.contacts.items[@intCast(cid - 1)];
    if (hp.port == 0) return;
    // не перезаписываем адрес логом при каждом чихе — только если изменился
    if (c.addr_len == hp.host.len and c.addr_port == hp.port and
        std.mem.eql(u8, c.addr_buf[0..c.addr_len], hp.host)) return;
    c.setAddr(hp.host, hp.port);
    if (app.log) |log| {
        logContact(app, log, c.getName(), c.bundle, host_port_str);
    }
}

/// Записать в лог последнюю запись outbox (вызов ПОД локом сразу после
/// sendText == .queued: она наша, очередь под локом).
fn persistOutboxAdd(app: *App) void {
    const log = app.log orelse return;
    const items = app.eng.outbox.items;
    if (items.len == 0) return;
    const e = items[items.len - 1];
    if (e.body.len > 4096) return;
    var buf: [3 + 16 + 8 + 2 + 4096]u8 = undefined;
    std.mem.writeInt(u16, buf[1..3], @intCast(e.cid), .little);
    buf[0] = 1;
    @memcpy(buf[3 .. 3 + 16], &e.msg_id);
    std.mem.writeInt(u64, buf[19..27], e.ts_ms, .little);
    std.mem.writeInt(u16, buf[27..29], @intCast(e.body.len), .little);
    @memcpy(buf[29 .. 29 + e.body.len], e.body);
    _ = log.append(.outbox, buf[0 .. 29 + e.body.len]) catch {};
}

/// Записать в лог погашение (ACK) записи outbox.
fn persistOutboxAck(app: *App, cid: i64, msg_id: [16]u8) void {
    const log = app.log orelse return;
    var buf: [3 + 16]u8 = undefined;
    buf[0] = 0;
    std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    _ = log.append(.outbox, &buf) catch {};
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
        // хвост адреса: [alen][host][port LE] (последняя запись побеждает)
        const c = &app.eng.contacts.items[idx];
        const tail = 1 + nlen + 64;
        if (rec.len >= tail + 1) {
            const alen: usize = rec[tail];
            if (alen > 0 and alen <= 64 and rec.len >= tail + 1 + alen + 2) {
                const port = std.mem.readInt(u16, rec[tail + 1 + alen ..][0..2], .little);
                c.setAddr(rec[tail + 1 .. tail + 1 + alen], port);
            }
        }
    }
    // outbox: добавление/погашение в порядке записи лога
    const obs = log.readAll(.outbox, app.alloc) catch return;
    defer {
        for (obs) |r| app.alloc.free(r);
        app.alloc.free(obs);
    }
    for (obs) |rec| {
        if (rec.len < 3) continue;
        const cid: i64 = @intCast(std.mem.readInt(u16, rec[1..3], .little));
        if (cid < 1 or cid > app.eng.contacts.items.len) continue;
        if (rec[0] == 0) {
            if (rec.len < 3 + 16) continue;
            const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
            var i: usize = 0;
            while (i < app.eng.outbox.items.len) {
                if (app.eng.outbox.items[i].cid == cid and std.mem.eql(u8, &app.eng.outbox.items[i].msg_id, &msg_id)) {
                    const old = app.eng.outbox.orderedRemove(i);
                    app.alloc.free(old.body);
                } else i += 1;
            }
            continue;
        }
        if (rec.len < 3 + 16 + 8 + 2) continue;
        const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
        const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
        const blen = std.mem.readInt(u16, rec[27..29], .little);
        if (blen == 0 or blen > 4096 or rec.len < 29 + blen) continue;
        const body = app.alloc.dupe(u8, rec[29 .. 29 + blen]) catch continue;
        app.eng.outbox.append(app.alloc, .{ .cid = cid, .msg_id = msg_id, .ts_ms = ts_ms, .body = body }) catch {
            app.alloc.free(body);
        };
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
/// Мини-билдер строк кадра: копирует байты и считает ЗАНЯТЫЕ КОЛОНКИ
/// (ANSI-эскейпы не считаются) — для выравнивания рамок.
const StrBuf = struct {
    buf: []u8,
    n: usize = 0,
    cols: usize = 0,
    in_esc: bool = false,

    fn init(buf: []u8) StrBuf {
        return .{ .buf = buf };
    }

    fn add(self: *StrBuf, bytes: []const u8) void {
        if (self.n + bytes.len > self.buf.len) return;
        @memcpy(self.buf[self.n .. self.n + bytes.len], bytes);
        self.n += bytes.len;
        var i: usize = 0;
        while (i < bytes.len) {
            const b = bytes[i];
            if (b == 0x1B) {
                self.in_esc = true;
                i += 1;
                continue;
            }
            if (self.in_esc) {
                if (b == 'm') self.in_esc = false;
                i += 1;
                continue;
            }
            const l = std.unicode.utf8ByteSequenceLength(b) catch 1;
            self.cols += 1;
            i += l;
        }
    }
};

/// Помощник записи в буфер кадра.
const W = struct {
    fn put(buf: []u8, n: *usize, bytes: []const u8) void {
        if (n.* + bytes.len > buf.len) return;
        @memcpy(buf[n.* .. n.* + bytes.len], bytes);
        n.* += bytes.len;
    }

    /// Строка панели: │ mid дополненный пробелами до cols │ (+перевод строки).
    /// used — колонки, занятые mid (по счётчику StrBuf).
    fn row(buf: []u8, n: *usize, mid: []const u8, used: usize, cols: usize) void {
        put(buf, n, tui_mod.c.dim);
        put(buf, n, "│");
        put(buf, n, tui_mod.c.reset);
        put(buf, n, mid);
        if (used < cols) {
            var pad: [256]u8 = @splat(' ');
            var left = cols - used;
            while (left > 0) {
                const chunk = @min(left, pad.len);
                put(buf, n, pad[0..chunk]);
                left -= chunk;
            }
        }
        put(buf, n, tui_mod.c.dim);
        put(buf, n, "│");
        put(buf, n, tui_mod.c.reset);
        put(buf, n, "\r\n");
    }

    /// Строка из простого текста (без цветов).
    fn rowPlain(buf: []u8, n: *usize, mid: []const u8, cols: usize) void {
        row(buf, n, mid, plainCols(mid), cols);
    }

    fn plainCols(s_: []const u8) usize {
        var cols: usize = 0;
        var i: usize = 0;
        while (i < s_.len) {
            const l = std.unicode.utf8ByteSequenceLength(s_[i]) catch 1;
            if (i + l > s_.len) break;
            cols += 1;
            i += l;
        }
        return cols;
    }
};

/// Двухпанельный мессенджер (голый ANSI):
/// слева список чатов (выбор, онлайн, возраст последнего пакета,
/// непрочитанные), справа лента с временем, шапка контакта и поле
/// ввода в рамке; внизу — строка клавиш. Полный кадр каждые 150 мс.
fn tuiLoop(app: *App) !void {
    app.tui = true;
    var kb = try tui_mod.Keyboard.init();
    defer kb.deinit();
    tui_mod.enterScreen();
    defer tui_mod.leaveScreen();

    var input: [512]u8 = undefined;
    var input_len: usize = 0;
    var scroll: u32 = 0; // строк от низа ленты
    var frame: [49152]u8 = undefined;

    while (app.running) {
        const n = renderTui(app, input[0..input_len], &scroll, &frame);
        tui_mod.writeAllRaw(frame[0..n]);

        const key = kb.poll(150);
        switch (key) {
            .none => {},
            .ctrl_c => app.running = false,
            .esc => input_len = 0,
            .enter => {
                if (input_len == 0) continue;
                scroll = 0;
                if (input[0] == '/') {
                    if (!execCmd(app, input[1..input_len])) app.running = false;
                } else {
                    app.lock();
                    const nc = app.eng.contacts.items.len;
                    if (nc == 0) {
                        app.sysLineLocked(null, "нет чатов: /add shopot1.код");
                    } else {
                        const cid: i64 = @intCast(app.sel + 1);
                        const name = app.eng.contacts.items[app.sel].getName();
                        const r = app.eng.sendText(cid, input[0..input_len]) catch |e| {
                            var eb: [64]u8 = undefined;
                            const t = std.fmt.bufPrint(&eb, "! ошибка: {s}", .{@errorName(e)}) catch "!";
                            app.sysLineLocked(app.sel, t);
                            return;
                        };
                        if (r == .queued) {
                            persistOutboxAdd(app);
                            app.sysLineLocked(app.sel, "в очереди: доставлю, когда контакт появится");
                        }
                        app.msgLineLocked(app.sel, .mine, name, input[0..input_len]);
                    }
                    app.unlock();
                }
                input_len = 0;
            },
            .tab => {
                app.lock();
                const nc = app.eng.contacts.items.len;
                if (nc > 0) {
                    app.sel = (app.sel + 1) % nc;
                    app.threads[app.sel].unread = 0;
                }
                app.unlock();
                scroll = 0;
            },
            .up => scroll +%= 1,
            .down => {
                if (scroll > 0) scroll -= 1;
            },
            .backspace => {
                if (input_len > 0) {
                    input_len -= 1;
                    while (input_len > 0 and (input[input_len] & 0xC0) == 0x80) input_len -= 1;
                }
            },
            .alt => |code| switch (code) {
                // Alt+q/Ctrl+C — выход; буквы всегда идут в текст ввода
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
                        const cid_str = std.fmt.bufPrint(&cb, "{d}", .{app.sel + 1}) catch continue;
                        cmdCall(app, cid_str) catch |e| {
                            fb(app, app.sel, fmtErr(&cb, "звонок", e));
                        };
                    } else fb(app, null, "нет чатов");
                    continue;
                },
                'a' => {
                    cmdAnswer(app) catch |e| {
                        var eb: [64]u8 = undefined;
                        const t2 = std.fmt.bufPrint(&eb, "! звонок: {s}", .{@errorName(e)}) catch "!";
                        fb(app, null, t2);
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
                    const blocked = if (nc > 0) app.eng.contacts.items[app.sel].blocked else false;
                    app.unlock();
                    if (nc > 0) {
                        var cb: [16]u8 = undefined;
                        const cid_str = std.fmt.bufPrint(&cb, "{d}", .{app.sel + 1}) catch continue;
                        cmdBlock(app, cid_str, !blocked) catch {};
                        fb(app, app.sel, if (!blocked) "контакт заблокирован" else "контакт разблокирован");
                    }
                    continue;
                },
                else => {},
            },
            .char => |ch| {
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

/// Сообщение для пользователя: в TUI — строка ленты, в REPL — печать.
fn fb(app: *App, idx: ?usize, txt: []const u8) void {
    // CLI-клиент ждёт ответа команды — отдаём ему, а не в терминал
    {
        app.cliLock();
        defer app.cliUnlock();
        if (app.cli_out) |c| {
            c.writeText(txt);
            return;
        }
    }
    if (app.tui) {
        app.lock();
        app.sysLineLocked(idx, txt);
        app.unlock();
    } else {
        std.debug.print("{s}\n", .{txt});
    }
}

fn fmtErr(buf: []u8, what: []const u8, e: anyerror) []const u8 {
    return std.fmt.bufPrint(buf, "! {s}: {s}", .{ what, @errorName(e) }) catch "!";
}

/// Полный кадр TUI. Возвращает длину записанного.
fn renderTui(app: *App, input: []const u8, scroll: *u32, frame: []u8) usize {
    const T = tui_mod;
    const sz = T.termSize();
    const w: usize = sz.w;
    const h: usize = sz.h;
    var n: usize = 0;
    // курсор в дом: каждый кадр перезаписывает экран поверх предыдущего
    W.put(frame, &n, "\x1b[H");

    if (w < 60 or h < 12) {
        W.put(frame, &n, T.c.dim);
        var msg: [64]u8 = undefined;
        const t = std.fmt.bufPrint(&msg, " терминал мал: нужно 60x12, сейчас {d}x{d} ", .{ w, h }) catch " мал ";
        W.put(frame, &n, t);
        W.put(frame, &n, T.c.reset);
        return n;
    }

    // сетка: │ сайдбар │ чат │
    const sw: usize = if (w >= 100) 28 else 24; // контент сайдбара
    const cw: usize = w - sw - 3; // контент чата
    const rows_msg: usize = h - 7; // строки ленты
    const name_w: usize = sw - 12; // имя в сайдбаре

    // ---------------- строка 0: ┌─ shopot · :7777 ──┬────┐
    W.put(frame, &n, T.c.dim);
    W.put(frame, &n, "┌");
    {
        var tb: [40]u8 = undefined;
        const title = std.fmt.bufPrint(&tb, " shopot · :{d} · LAN ", .{app.listen_port}) catch " shopot ";
        const tl = @min(title.len, sw);
        W.put(frame, &n, T.c.cyan);
        W.put(frame, &n, T.c.bold);
        W.put(frame, &n, title[0..tl]);
        W.put(frame, &n, T.c.reset);
        W.put(frame, &n, T.c.dim);
        var k: usize = 0;
        while (k < sw - tl) : (k += 1) W.put(frame, &n, "─");
    }
    W.put(frame, &n, "┬");
    var k2: usize = 0;
    while (k2 < cw) : (k2 += 1) W.put(frame, &n, "─");
    W.put(frame, &n, "┐");
    W.put(frame, &n, T.c.reset);
    W.put(frame, &n, "\r\n");

    // ---------------- строка 1: шапки панелей
    {
        var mid_s: [64]u8 = undefined;
        var sb = StrBuf.init(&mid_s);
        app.lock();
        const nc = app.eng.contacts.items.len;
        var online_cnt: usize = 0;
        for (app.eng.contacts.items) |ct| {
            if (ct.online and !ct.blocked) online_cnt += 1;
        }
        sb.add(T.c.bold);
        sb.add(" ЧАТЫ");
        sb.add(T.c.reset);
        sb.add(T.c.dim);
        var cnt: [24]u8 = undefined;
        const cts = std.fmt.bufPrint(&cnt, "  {d}/{d} online", .{ online_cnt, nc }) catch "";
        sb.add(cts);
        sb.add(T.c.reset);

        var mid_c: [160]u8 = undefined;
        var cb = StrBuf.init(&mid_c);
        if (nc > 0) {
            const ct = app.eng.contacts.items[app.sel];
            var nb: [24]u8 = undefined;
            const name = T.trunc(&nb, ct.getName(), 16);
            cb.add(" ");
            cb.add(T.c.bold);
            cb.add(name);
            cb.add(T.c.reset);
            if (ct.blocked) {
                cb.add("  ");
                cb.add(T.c.red);
                cb.add("✕ заблокирован");
                cb.add(T.c.reset);
            } else if (app.call) |cc| {
                if (cc.cid == @as(i64, @intCast(app.sel + 1))) {
                    var db: [12]u8 = undefined;
                    const dur = T.fmtDur(&db, app.nowMs() - cc.start_ms);
                    cb.add("  ");
                    cb.add(T.c.yellow);
                    cb.add(T.c.bold);
                    cb.add("ЗВОНОК ");
                    cb.add(dur);
                    cb.add(T.c.reset);
                }
            }
            if (!ct.blocked and (app.call == null or app.call.?.cid != @as(i64, @intCast(app.sel + 1)))) {
                if (ct.online) {
                    const seen = app.eng.lastSeen(@intCast(app.sel + 1)) orelse 0;
                    var ab: [12]u8 = undefined;
                    const age = T.fmtAge(&ab, app.nowMs() - seen);
                    cb.add("  ");
                    cb.add(T.c.green);
                    cb.add("● ");
                    cb.add(age);
                    cb.add(T.c.reset);
                } else {
                    cb.add("  ");
                    cb.add(T.c.dim);
                    cb.add("○ офлайн");
                    cb.add(T.c.reset);
                }
            }
        } else {
            cb.add(T.c.dim);
            cb.add(" нет чата — /add shopot1.код");
            cb.add(T.c.reset);
        }
        app.unlock();
        W.row(frame, &n, mid_s[0..sb.n], sb.cols, sw);
        W.row(frame, &n, mid_c[0..cb.n], cb.cols, cw);
    }

    // ---------------- строка 2: пересечения ├──┼──┤
    W.put(frame, &n, T.c.dim);
    W.put(frame, &n, "├");
    var k3: usize = 0;
    while (k3 < sw) : (k3 += 1) W.put(frame, &n, "─");
    W.put(frame, &n, "┼");
    var k4: usize = 0;
    while (k4 < cw) : (k4 += 1) W.put(frame, &n, "─");
    W.put(frame, &n, "┤");
    W.put(frame, &n, T.c.reset);
    W.put(frame, &n, "\r\n");

    // ---------------- данные под лок (снапшот в стек)
    app.lock();
    const nc = app.eng.contacts.items.len;
    const sel: ?usize = if (app.sel < nc) app.sel else null;
    const now = app.nowMs();

    var entry_buf: [18][96]u8 = undefined;
    var entry_cols: [18]usize = @splat(0);
    var entry_len: [18]usize = @splat(0);
    const max_entries: usize = @min(rows_msg + 2, entry_buf.len);
    var shown_entries: usize = 0;
    {
        var i: usize = 0;
        while (i < nc and shown_entries < max_entries) : (i += 1) {
            const ct = app.eng.contacts.items[i];
            var sb = StrBuf.init(&entry_buf[shown_entries]);
            if (i == app.sel) {
                sb.add(T.c.cyan);
                sb.add(T.c.bold);
                sb.add("› ");
            } else sb.add("  ");
            sb.add(T.c.reset);
            var nb: [28]u8 = undefined;
            const name = T.trunc(&nb, ct.getName(), name_w);
            var padname: [30]u8 = @splat(' ');
            @memcpy(padname[0..name.len], name);
            sb.add(padname[0..name_w]);
            if (ct.blocked) {
                sb.add(T.c.red);
                sb.add("✕");
                sb.add(T.c.reset);
            } else if (ct.online) {
                sb.add(T.c.green);
                sb.add("●");
                sb.add(T.c.reset);
                const seen = app.eng.lastSeen(@intCast(i + 1)) orelse 0;
                var ab: [10]u8 = undefined;
                const age = T.fmtAge(&ab, now - seen);
                var agepad: [8]u8 = @splat(' ');
                var al: usize = 0;
                while (al + age.len < 5) : (al += 1) {}
                sb.add(T.c.dim);
                sb.add(agepad[0..al]);
                sb.add(age);
                sb.add(T.c.reset);
            } else {
                sb.add(T.c.dim);
                sb.add("○");
                sb.add(T.c.reset);
            }
            if (i != app.sel and app.threads[i].unread > 0) {
                var ub: [12]u8 = undefined;
                const us = std.fmt.bufPrint(&ub, " {d}", .{app.threads[i].unread}) catch "";
                sb.add(T.c.cyan);
                sb.add(T.c.bold);
                sb.add(us);
                sb.add(T.c.reset);
            }
            entry_cols[shown_entries] = sb.cols;
            entry_len[shown_entries] = sb.n;
            shown_entries += 1;
        }
    }

    var msg_buf: [48][300]u8 = undefined;
    var msg_cols: [48]usize = @splat(0);
    var msg_len: [48]usize = @splat(0);
    var shown_msgs: usize = 0;
    if (sel) |si| {
        const th = &app.threads[si];
        if (th.count == 0) {
            var sb = StrBuf.init(&msg_buf[0]);
            sb.add(T.c.dim);
            sb.add(" нет сообщений — напишите первое");
            sb.add(T.c.reset);
            msg_cols[0] = sb.cols;
            msg_len[0] = sb.n;
            shown_msgs = 1;
        } else {
            var sp = scroll.*;
            if (sp >= th.count) sp = @intCast(th.count - 1);
            scroll.* = sp;
            var show: usize = @min(th.count, rows_msg);
            if (sp > 0 and show > 1) show -= 1;
            var base: usize = th.count - show;
            if (base >= sp) base -= sp else base = 0;
            var r: usize = 0;
            while (r < show and r < msg_buf.len) : (r += 1) {
                const line = th.at(@intCast(base + r));
                var sb = StrBuf.init(&msg_buf[r]);
                var tsb: [8]u8 = undefined;
                const clock = T.fmtClock(&tsb, line.ts, app.tz);
                sb.add(T.c.dim);
                sb.add(" ");
                sb.add(clock);
                sb.add("  ");
                switch (line.kind) {
                    .mine => {
                        sb.add(T.c.reset);
                        sb.add(T.c.green);
                        sb.add(T.c.bold);
                        sb.add("я");
                        sb.add(T.c.reset);
                        // колонка автора — фикс. 12, как у theirs: текст ровно
                        var padme: [14]u8 = @splat(' ');
                        sb.add(padme[0..11]);
                        sb.add("  ");
                    },
                    .theirs => {
                        sb.add(T.c.reset);
                        sb.add(T.c.cyan);
                        sb.add(T.c.bold);
                        var nb: [26]u8 = undefined;
                        const name = T.trunc(&nb, line.name(), 12);
                        var padn: [14]u8 = @splat(' ');
                        @memcpy(padn[0..name.len], name);
                        sb.add(padn[0..12]);
                        sb.add(T.c.reset);
                        sb.add("  ");
                    },
                    .sys => {
                        sb.add(T.c.dim);
                    },
                }
                const budget = if (sb.cols < cw) cw - sb.cols else 0;
                var tb: [208]u8 = undefined;
                const txt = T.trunc(&tb, line.text(), budget);
                sb.add(txt);
                sb.add(T.c.reset);
                msg_cols[r] = sb.cols;
                msg_len[r] = sb.n;
                shown_msgs += 1;
            }
        }
    }
    app.unlock();

    // ---------------- строки контента
    var row_i: usize = 0;
    while (row_i < rows_msg) : (row_i += 1) {
        if (row_i < shown_entries) {
            W.row(frame, &n, entry_buf[row_i][0..entry_len[row_i]], entry_cols[row_i], sw);
        } else if (nc == 0 and row_i == shown_entries) {
            W.rowPlain(frame, &n, " нет чатов", sw);
        } else {
            W.rowPlain(frame, &n, " ", sw);
        }
        if (row_i < shown_msgs) {
            W.row(frame, &n, msg_buf[row_i][0..msg_len[row_i]], msg_cols[row_i], cw);
        } else if (sel == null and row_i == 0) {
            W.rowPlain(frame, &n, " добавьте контакт: /add shopot1.код", cw);
        } else {
            W.rowPlain(frame, &n, " ", cw);
        }
    }

    // ---------------- ряды h-4 (сепаратор ввода) и h-3 (ввод)
    {
        var s1: [96]u8 = undefined;
        var s1c: usize = 0;
        var s1l: usize = 0;
        var s2: [96]u8 = undefined;
        var s2c: usize = 0;
        var s2l: usize = 0;
        if (rows_msg < shown_entries) {
            s1c = entry_cols[rows_msg];
            s1l = entry_len[rows_msg];
            @memcpy(s1[0..s1l], entry_buf[rows_msg][0..s1l]);
        }
        if (rows_msg + 1 < shown_entries) {
            s2c = entry_cols[rows_msg + 1];
            s2l = entry_len[rows_msg + 1];
            @memcpy(s2[0..s2l], entry_buf[rows_msg + 1][0..s2l]);
        }

        // ряд h-4: │ сайдбар │ ───────── │
        W.put(frame, &n, T.c.dim);
        W.put(frame, &n, "│");
        W.put(frame, &n, T.c.reset);
        W.put(frame, &n, s1[0..s1l]);
        if (s1c < sw) {
            var pad: [96]u8 = @splat(' ');
            W.put(frame, &n, pad[0 .. sw - s1c]);
        }
        W.put(frame, &n, T.c.dim);
        W.put(frame, &n, "│");
        W.put(frame, &n, T.c.reset);
        W.put(frame, &n, T.c.dim);
        var kk: usize = 0;
        while (kk < cw) : (kk += 1) W.put(frame, &n, "─");
        W.put(frame, &n, "│");
        W.put(frame, &n, T.c.reset);
        W.put(frame, &n, "\r\n");

        // ряд h-3: │ сайдбар │ ввод │
        var ib: [600]u8 = undefined;
        var sb = StrBuf.init(&ib);
        sb.add(" ");
        sb.add(T.c.green);
        sb.add(T.c.bold);
        sb.add("›");
        sb.add(T.c.reset);
        sb.add(" ");
        var txt: [520]u8 = undefined;
        const ti = T.trunc(&txt, input, cw - 4);
        sb.add(ti);
        if (sb.cols + 1 < cw) sb.add("▌");
        W.put(frame, &n, T.c.dim);
        W.put(frame, &n, "│");
        W.put(frame, &n, T.c.reset);
        W.put(frame, &n, s2[0..s2l]);
        if (s2c < sw) {
            var pad2: [96]u8 = @splat(' ');
            W.put(frame, &n, pad2[0 .. sw - s2c]);
        }
        W.put(frame, &n, T.c.dim);
        W.put(frame, &n, "│");
        W.put(frame, &n, T.c.reset);
        W.put(frame, &n, ib[0..sb.n]);
        if (sb.cols < cw) {
            var pad3: [600]u8 = @splat(' ');
            W.put(frame, &n, pad3[0 .. cw - sb.cols]);
        }
        W.put(frame, &n, T.c.dim);
        W.put(frame, &n, "│");
        W.put(frame, &n, T.c.reset);
        W.put(frame, &n, "\r\n");
    }

    // ---------------- низ: └────┴────┘
    W.put(frame, &n, T.c.dim);
    W.put(frame, &n, "└");
    var k5: usize = 0;
    while (k5 < sw) : (k5 += 1) W.put(frame, &n, "─");
    W.put(frame, &n, "┴");
    var k6: usize = 0;
    while (k6 < cw) : (k6 += 1) W.put(frame, &n, "─");
    W.put(frame, &n, "┘");
    W.put(frame, &n, T.c.reset);
    W.put(frame, &n, "\r\n");

    // ---------------- подсказки (вне рамки)
    W.put(frame, &n, T.c.dim);
    var hints: [256]u8 = undefined;
    const hl = T.trunc(&hints, " enter отправить · tab чат · ↑↓ лента · /cmd · Alt+c звонок · Alt+a принять · Alt+h сброс · Alt+b блок", w - 1);
    W.put(frame, &n, hl);
    W.put(frame, &n, T.c.reset);

    return n;
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
pub fn execCmd(app: *App, trimmed: []const u8) bool {
    var errbuf: [96]u8 = undefined;
    var it = std.mem.tokenizeAny(u8, trimmed, " ");
    const cmd = it.next() orelse return true;
    const rest = std.mem.trim(u8, trimmed[cmd.len..], " ");

    if (std.mem.eql(u8, cmd, "help")) {
        fb(app, null, "invite <имя> · add <код|hex> · msg <id> <текст> · react · block/unblock <id>");
        fb(app, null, "call <id> · answer · hangup · contacts · connect <addr:port> <id> · listen · quit");
    } else if (std.mem.eql(u8, cmd, "quit") or std.mem.eql(u8, cmd, "q")) {
        app.running = false;
    } else if (std.mem.eql(u8, cmd, "contacts")) {
        cmdContacts(app);
    } else if (std.mem.eql(u8, cmd, "invite")) {
        cmdInvite(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "приглашение", e));
    } else if (std.mem.eql(u8, cmd, "add")) {
        cmdAdd(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "add", e));
    } else if (std.mem.eql(u8, cmd, "msg")) {
        cmdMsg(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "msg", e));
    } else if (std.mem.eql(u8, cmd, "react")) {
        cmdReact(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "react", e));
    } else if (std.mem.eql(u8, cmd, "block")) {
        cmdBlock(app, rest, true) catch |e| fb(app, null, fmtErr(&errbuf, "block", e));
    } else if (std.mem.eql(u8, cmd, "unblock")) {
        cmdBlock(app, rest, false) catch |e| fb(app, null, fmtErr(&errbuf, "unblock", e));
    } else if (std.mem.eql(u8, cmd, "call")) {
        cmdCall(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "звонок", e));
    } else if (std.mem.eql(u8, cmd, "answer")) {
        cmdAnswer(app) catch |e| fb(app, null, fmtErr(&errbuf, "звонок", e));
    } else if (std.mem.eql(u8, cmd, "hangup")) {
        cmdHangup(app) catch |e| fb(app, null, fmtErr(&errbuf, "звонок", e));
    } else if (std.mem.eql(u8, cmd, "connect")) {
        var ait = std.mem.tokenizeAny(u8, rest, " ");
        const addr = ait.next() orelse return true;
        const cid = std.fmt.parseInt(i64, ait.next() orelse return true, 10) catch return true;
        establishTo(app, addr, cid, .initiator) catch |e|
            fb(app, null, fmtErr(&errbuf, "connect", e));
    } else if (std.mem.eql(u8, cmd, "listen")) {
        var ait = std.mem.tokenizeAny(u8, rest, " ");
        const addr = ait.next() orelse return true;
        const cid = std.fmt.parseInt(i64, ait.next() orelse return true, 10) catch return true;
        const lsn = tcp.listen(addr) catch |e| {
            fb(app, null, fmtErr(&errbuf, "listen", e));
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
        fb(app, null, "не знаю команду — /help для списка");
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

    if (std.mem.eql(u8, cmd, "chat") or std.mem.eql(u8, cmd, "serve")) {
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

        // переписки для TUI: heap-массив (стеку 12+ МБ не отдавать)
        const threads = alloc.alloc(tui_mod.Thread, 256) catch
            return error.OutOfMemory;
        // alloc возвращает сырую память (DebugAllocator заполняет 0xAA):
        // каждый Thread обязан получить значения полей по умолчанию
        for (threads) |*t| t.* = .{};
        var app = App{
            .alloc = alloc,
            .io = io,
            .id = &id,
            .eng = &eng,
            .log = log_ptr,
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *SessCtx).init(alloc),
            .call_pcm_dir = if (pcm_heap.len > 0) pcm_heap else null,
            .threads = threads,
            .tz = tui_mod.tzOffset(),
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

        // CLI-фронт-енд: UDS-апи
        cli_srv.start(&app, home);

        // интерактивный терминал — полноэкранный TUI; иначе — построчный REPL;
        // serve — безлокальный демон для CLI-клиентов (UDS)
        const is_tty = blk: {
            _ = std.posix.tcgetattr(0) catch break :blk false;
            break :blk true;
        };
        if (std.mem.eql(u8, cmd, "serve")) {
            std.debug.print("serve: работаю без локального ввода, жду CLI-клиентов\n", .{});
            while (app.running) {
                const req: std.os.linux.timespec = .{ .sec = 1, .nsec = 0 };
                _ = std.os.linux.nanosleep(&req, null);
            }
        } else if (is_tty) {
            try tuiLoop(&app);
        } else {
            try repl(&app);
        }

        eng.deinit();
        return;
    }

    std.debug.print("{s}\n", .{usage});
}
