//! shopot-zig: ядро шифрованного мессенджера. Только std, никаких JSON.
//! Интерфейс для клиентов — UDS-апи (cli_server.zig, см. docs/CORE-API.md).
//! Контакты, история и блокировки — в шифрованном логе (~/.shopot/zig-log).
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
const adpcm_mod = @import("adpcm.zig");
const cli_srv = @import("cli_server.zig");
const cli_mod = cli_srv;

const usage =
    \\shopot-zig — ядро шифрованного мессенджера (std-only Zig).
    \\Клиенты подключаются через UDS-апи ($HOME/.shopot/api.sock),
    \\интерактивного CLI нет. Справка по API — docs/CORE-API.md.
    \\
    \\  init    создать личность (~/.shopot/zig-seed, 0600)
    \\  id      показать bundle и отпечаток
    \\  serve   демон: ядро + UDS-апи (см. docs/CORE-API.md)
;
const app_home_max = 512;

/// $HOME копия App.home_buf.
fn appHomeDir(app: *const App) []const u8 {
    return app.home_buf[0..app.home_len];
}

fn shopotDir(io: std.Io, home: []const u8) ![512]u8 {
    if (home.len == 0) return error.NoHome;
    var buf: [512]u8 = undefined;
    // 0700: каталог с сидом/логом/сокетом — только владелец
    std.Io.Dir.createDirAbsolute(io, try std.fmt.bufPrint(&buf, "{s}/.shopot", .{home}), @fromBackingInt(@intCast(0o700))) catch {};
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

pub fn toHex(out: []u8, bytes: []const u8) ![]u8 {
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
    // ---- UDS-апи (единственный интерфейс для клиентов) ----
    cli: ?*cli_srv.Server = null, // сервер (включён, когда != null)
    cli_out: ?*cli_srv.Conn = null, // кому fb отдаёт ответы команд (под cli_mu)
    cli_mu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false), // приёмник fb-ответов

    // ---- Односторонние инвайты (v2) ----
    /// Выданные приглашения: секрет ждёт предъявителя JOIN-конвертом.
    invites: [4]InviteReg = @splat(.{}),
    /// JOIN-данные по cid: отправить первым конвертом после рукопожатия.
    join_map: std.AutoHashMapUnmanaged(i64, JoinInfo) = .empty,
    /// Кэш аватаров: avatar_id -> байты (из лога kind AVATAR).
    avatars: std.AutoHashMapUnmanaged([16]u8, []u8) = .empty,
    /// Живые fake-TLS обёртки (для deinit по завершении).
    ftlss: std.ArrayListUnmanaged(*shopot.net.faketls.FakeTlsConn) = .empty,
    /// Приём файлов в полёте: file_id -> RxFile.
    rx_files: std.AutoHashMapUnmanaged([16]u8, *RxFile) = .empty,
    /// Копия $HOME (для файлов/путей).
    home_buf: [512]u8 = @splat(0),
    home_len: usize = 0,

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
        // PROFILE-эхо: имя + avatar_id пир-у при каждом установлении
        self.eng.sendProfile(cid) catch {};
    }

    fn events(self: *App) engine_mod.Events {
        return .{ .ctx = self, .onText = onTextEv, .onReaction = onReactionEv, .onPresence = onPresenceEv, .onBlockedNotice = onBlockedEv, .onCallSignal = onCallSignalEv, .onCallAudio = onCallAudioEv, .onDelivered = onDeliveredEv, .onAvatar = onAvatarEv, .onAvatarReq = onAvatarReqEv, .onFileMeta = onFileMetaEv, .onFileData = onFileDataEv };
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
    const now = app.nowMs();
    persistMsg(app, @intCast(idx + 1), false, msg_id, true, now, body);
    // машиночитаемое событие: imsg <cid> <имя> <msg_id_hex> <ts> <текст>
    cli_srv.fanoutImsgLocked(app, @intCast(idx + 1), from.getName(), msg_id, now, body);
    if (app.tui) {
        app.msgLineLocked(idx, .theirs, from.getName(), body);
    } else {
        std.debug.print("\n<< [{s}] {s}  (msg {s})\n> ", .{ from.getName(), body, hx });
    }
    cli_srv.fanoutMsgLocked(app, @intCast(idx + 1), from.getName(), body);
}

/// Получен аватар: кэш (память + лог), фанаут события avatar <cid> <id_hex>.
fn onAvatarEv(ctx: *anyopaque, from: *const engine_mod.Contact, avatar_id: [16]u8, data: []const u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    // кэш: могли уже положить (дедуп по id)
    if (!app.avatars.contains(avatar_id)) {
        const copy = app.alloc.dupe(u8, data) catch return;
        app.avatars.put(app.alloc, avatar_id, copy) catch {
            app.alloc.free(copy);
            return;
        };
        if (app.log) |log| {
            var buf: [18 + 16000]u8 = undefined;
            @memcpy(buf[0..16], &avatar_id);
            std.mem.writeInt(u16, buf[16..18], @intCast(data.len), .little);
            @memcpy(buf[18 .. 18 + data.len], data);
            _ = log.append(.avatar, buf[0 .. 18 + data.len]) catch {};
        }
    }
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &avatar_id) catch return;
    var line: [96]u8 = undefined;
    const t = std.fmt.bufPrint(&line, "аватар {s}: {d} байт", .{ from.getName(), data.len }) catch return;
    if (app.tui) {
        app.sysLineLocked(idx, t);
    } else {
        std.debug.print("\n<< {s}\n> ", .{t});
    }
    var ml: [64]u8 = undefined;
    const mt = std.fmt.bufPrint(&ml, "avatar {s}", .{hx}) catch return;
    cli_srv.fanoutSysLocked(app, @intCast(idx + 1), from.getName(), mt);
}

/// FILE_META: начать приём файла (состояние под app.mu).
fn onFileMetaEv(ctx: *anyopaque, from: *const engine_mod.Contact, meta: envelope.FileMeta) void {
    _ = from;
    const app: *App = @ptrCast(@alignCast(ctx));
    if (app.rx_files.contains(meta.file_id)) return; // уже в полёте
    if (fileAlreadyStored(app, meta.file_id)) return; // уже приняли ранее
    const rx = app.alloc.create(RxFile) catch return;
    rx.* = .{ .size = meta.size, .sha = meta.sha };
    const n = @min(meta.name.len, envelope.max_file_name);
    @memcpy(rx.name_buf[0..n], meta.name[0..n]);
    rx.name_len = n;
    app.rx_files.put(app.alloc, meta.file_id, rx) catch {
        app.alloc.destroy(rx);
        return;
    };
}

/// Чанк FILE_DATA: копим; по последнему чанку — сверка SHA и сохранение.
/// ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn).
fn onFileDataEv(ctx: *anyopaque, from: *const engine_mod.Contact, data: envelope.FileData) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const rx = app.rx_files.get(data.file_id) orelse return;
    if (data.seq != rx.expected_seq) return; // дубликат/дыра: ждём свой
    rx.expected_seq += 1;
    rx.buf.appendSlice(app.alloc, data.data) catch return;
    if (rx.buf.items.len < rx.size) return;
    if (rx.buf.items.len != rx.size) { // перелив = поломка передачи
        dropRxFile(app, data.file_id);
        return;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(rx.buf.items, &digest, .{});
    if (!std.mem.eql(u8, &digest, &rx.sha)) { // битые байты
        dropRxFile(app, data.file_id);
        return;
    }
    const cid = contactIdByBundle(app, from.bundle) orelse {
        dropRxFile(app, data.file_id);
        return;
    };
    if (!saveRxFile(app, data.file_id, rx.buf.items)) {
        dropRxFile(app, data.file_id);
        return;
    }
    // лог kind FILE — перезапрос после рестарта не нужен
    persistFileMeta(app, @intCast(cid), data.file_id, rx.size, rx.name());
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &data.file_id) catch {
        dropRxFile(app, data.file_id);
        return;
    };
    var line: [192]u8 = undefined;
    const t = std.fmt.bufPrint(&line, "file {d} {s} {d} {s}", .{ cid, hx, rx.size, rx.name() }) catch {
        dropRxFile(app, data.file_id);
        return;
    };
    dropRxFile(app, data.file_id);
    cli_srv.fanoutSysLocked(app, cid, "file", t);
}

fn dropRxFile(app: *App, file_id: [16]u8) void {
    const rx = app.rx_files.get(file_id) orelse return;
    _ = app.rx_files.remove(file_id);
    rx.buf.deinit(app.alloc);
    std.crypto.secureZero(u8, &rx.sha);
    app.alloc.destroy(rx);
}

/// Файл уже сохранён? (кэш ~/.shopot/files/<id_hex32>)
fn fileAlreadyStored(app: *App, file_id: [16]u8) bool {
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &file_id) catch return false;
    var fbuf: [700]u8 = undefined;
    const path = std.fmt.bufPrint(&fbuf, "{s}/.shopot/files/{s}", .{ appHomeDir(app), hx }) catch return false;
    var zbuf: [701]u8 = undefined;
    @memcpy(zbuf[0..path.len], path);
    zbuf[path.len] = 0;
    const fd = std.os.linux.openat(@bitCast(@as(i32, -100)), @ptrCast(&zbuf), .{ .ACCMODE = .RDONLY }, 0);
    if (std.os.linux.errno(fd) != .SUCCESS) return false;
    _ = std.os.linux.close(@intCast(fd));
    return true;
}

/// Сохранить принятый файл (SHA уже сверена). true = записан.
fn saveRxFile(app: *App, file_id: [16]u8, bytes: []const u8) bool {
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &file_id) catch return false;
    var pbuf: [600]u8 = undefined;
    const dir = std.fmt.bufPrint(&pbuf, "{s}/.shopot/files", .{appHomeDir(app)}) catch return false;
    var zbuf: [601]u8 = undefined;
    @memcpy(zbuf[0..dir.len], dir);
    zbuf[dir.len] = 0;
    _ = std.os.linux.mkdir(@ptrCast(&zbuf), 0o700); // EEXIST — не ошибка
    var fbuf: [700]u8 = undefined;
    const path = std.fmt.bufPrint(&fbuf, "{s}/{s}", .{ dir, hx }) catch return false;
    var zbuf2: [701]u8 = undefined;
    @memcpy(zbuf2[0..path.len], path);
    zbuf2[path.len] = 0;
    const fd = std.os.linux.openat(@bitCast(@as(i32, -100)), @ptrCast(&zbuf2), .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600);
    if (std.os.linux.errno(fd) != .SUCCESS) return false;
    defer _ = std.os.linux.close(@intCast(fd));
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = std.os.linux.write(@intCast(fd), bytes[off..].ptr, bytes.len - off);
        if (std.os.linux.errno(rc) != .SUCCESS) return false;
        off += @intCast(rc);
    }
    return true;
}

/// Пир просит аватар с id: перекачать, если это наш текущий.
fn onAvatarReqEv(ctx: *anyopaque, from: *const engine_mod.Contact, avatar_id: [16]u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    const cid: i64 = @intCast(idx + 1);
    // наш текущий аватар? (самоисцеление: profile сказал id, мы перекачали)
    if (!std.mem.eql(u8, &app.eng.my_avatar_id, &avatar_id)) return;
    const data = app.avatars.get(avatar_id) orelse return;
    _ = app.eng.sendAvatar(cid, data) catch {};
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
    var glyph: [4]u8 = undefined;
    const glyph_len = std.unicode.utf8Encode(@intCast(r.code), &glyph) catch 0;
    var line: [160]u8 = undefined;
    const t = std.fmt.bufPrint(&line, "реакция {s} (U+{X:0>4}) на {s}", .{ glyph[0..glyph_len], r.code, toHex(&hex_buf, &r.msg_id) catch "?" }) catch return;
    if (app.tui) {
        app.sysLineLocked(idx, t);
    } else {
        std.debug.print("\n<< [{s}] {s}\n> ", .{ from.getName(), t });
    }
    persistReact(app, @intCast(idx + 1), false, r.msg_id, r.code, app.nowMs());
    // машиночитаемое событие для UDS-клиентов: react <msg_id_hex> <codepoint>
    var ml: [64]u8 = undefined;
    const mt = std.fmt.bufPrint(&ml, "react {s} {d}", .{ toHex(&hex_buf, &r.msg_id) catch "?", r.code }) catch return;
    cli_srv.fanoutSysLocked(app, @intCast(idx + 1), from.getName(), mt);
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
            cli_srv.fanoutCallLocked(app, cid, "offer", call_id);
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
            cli_srv.fanoutCallLocked(app, c.cid, "accept", call_id);
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
            cli_srv.fanoutCallLocked(app, c.cid, "reject", call_id);
            endCallLocked(app, "отклонён", call_id);
        },
        audio_mod.CallOp.hangup => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            endCallLocked(app, "повесил трубку", call_id);
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
    // провод: [codec u8][AEAD-блок]; codec 1 = PCM, 2 = ADPCM
    if (data.len < 1 + aead_min) return;
    var plain: [audio_mod.frame_bytes]u8 = undefined; // вместимость для PCM
    const n = audio_mod.openFrame(&plain, c.secret, c.call_id, seq, data[1..]) catch return;
    var pcm_buf: [audio_mod.frame_bytes]u8 = undefined;
    var play: []const u8 = undefined;
    switch (data[0]) {
        audio_mod.codec_pcm => {
            if (n != audio_mod.frame_bytes) return;
            play = plain[0..n];
        },
        audio_mod.codec_adpcm => {
            if (n != audio_mod.adpcm_block) return;
            const got = adpcm_mod.decodeBlock(&pcm_buf, plain[0..n]);
            if (got != audio_mod.frame_bytes) return;
            play = pcm_buf[0..got];
        },
        else => return, // неизвестный кодек: кадр отброшен
    }
    if (c.pcm) |*pcm| pcm.writeFrame(play);
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
    var acc: [audio_mod.frame_bytes]u8 = @splat(0); // 640 байт = 20 мс @ 16 кГц
    var acc_len: usize = 0;
    var silent_run: u32 = 0;
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
        const frame_seq = c.seq;
        // seq u32 в кадре CALL_AUDIO: на максимуме ключ/nonce кадра начали бы
        // повторяться — обрываем звонок раньше (практически недостижимо: ~99 суток)
        if (frame_seq == std.math.maxInt(u32)) {
            endCallLocked(app, "достигнут предел длины звонка", c.call_id);
            continue;
        }
        // DTX: тишину не шлём (каждый 25-й кадр — keepalive, чтобы пир знал:
        // линия жива). Пустое fifo читается как нули.
        const is_silent = isZero(acc[0..]);
        if (is_silent and silent_run < 24) {
            silent_run += 1;
            acc_len = 0;
            continue;
        }
        silent_run = 0;
        // кодек: IMA-ADPCM 4:1 -> 181 байт на проводе вместо 657
        var wbuf: [1 + audio_mod.adpcm_block + aead_min]u8 = undefined;
        var blk: [audio_mod.adpcm_block]u8 = undefined;
        if (is_silent) {
            @memset(&blk, 0);
        } else {
            _ = adpcm_mod.encodeBlock(&blk, acc[0..]);
        }
        wbuf[0] = audio_mod.codec_adpcm;
        const sealed = audio_mod.sealFrame(wbuf[1..], c.secret, c.call_id, frame_seq, &blk);
        acc_len = 0;
        c.seq = frame_seq + 1;
        _ = app.eng.callAudio(c.cid, frame_seq, wbuf[0 .. 1 + sealed]) catch {};
    }
}

const aead_min = 16; // aead.tag_length

fn isZero(b: []const u8) bool {
    for (b) |x| if (x != 0) return false;
    return true;
}

/// Завершить звонок: остановить поток, закрыть аудио, освободить состояние.
fn endCallLocked(app: *App, why: []const u8, call_id: [16]u8) void {
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
    cli_srv.fanoutCallLocked(app, cid, "end", call_id);
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
    cli_srv.fanoutCallLocked(app, cid, "offer", call_id);
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
    cli_srv.fanoutCallLocked(app, c.cid, "accept", c.call_id);
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
    endCallLocked(app, "вы повесили трубку", c.call_id);
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
        // весь провод завёрнут в fake-TLS: обёртку ставим ДО чтения m1,
        // кадр m1 [len u16][64] приходит внутри записей application_data
        const raw = faketlsServer(app, tc) catch {
            tc.deinit();
            continue;
        };
        var hdr: [2]u8 = undefined;
        raw.readAll(&hdr) catch {
            tc.deinit();
            continue;
        };
        const m1_len = std.mem.readInt(u16, &hdr, .little);
        if (m1_len != 64) {
            tc.deinit();
            continue;
        }
        var m1: [64]u8 = undefined;
        raw.readAll(&m1) catch {
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
                    raw,
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
            raw,
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

/// id: свой bundle и отпечаток (сверка голосом/QR между пользователями).
fn cmdId(app: *App) void {
    app.lock();
    defer app.unlock();
    const bundle = app.id.bundle();
    var hex_buf: [130]u8 = undefined;
    const hx = toHex(&hex_buf, &bundle) catch return;
    var fp_buf: [96]u8 = undefined;
    const fp = app.id.fingerprintTo(&fp_buf) catch return;
    var lb: [160]u8 = undefined;
    const l1 = std.fmt.bufPrint(&lb, "bundle {s}", .{hx}) catch return;
    fb(app, null, l1);
    var lb2: [128]u8 = undefined;
    const l2 = std.fmt.bufPrint(&lb2, "fingerprint {s}", .{fp}) catch return;
    fb(app, null, l2);
}

fn cmdContacts(app: *App, rest: []const u8) void {
    // contacts -m: машиночитаемо — c <cid> <online|offline> <blocked> <имя>
    const machine = std.mem.startsWith(u8, std.mem.trim(u8, rest, " "), "-m");
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
            if (machine) {
                const t = std.fmt.bufPrint(&lines_buf[n], "c {d} {s} {d} {s}", .{
                    cid,
                    if (c.online) "online" else "offline",
                    @intFromBool(c.blocked),
                    c.getName(),
                }) catch continue;
                lens[n] = t.len;
                n += 1;
                continue;
            }
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
        fb(app, null, if (machine) "c_end 0" else "нет контактов");
        return;
    }
    for (lines_buf[0..n], lens[0..n]) |*line, l| {
        fb(app, null, line[0..l]);
    }
    if (machine) {
        var fb2: [24]u8 = undefined;
        const t = std.fmt.bufPrint(&fb2, "c_end {d}", .{n}) catch return;
        fb(app, null, t);
    }
}

/// Состояние приёма одного файла (FILE_META + чанки FILE_DATA).
const RxFile = struct {
    name_buf: [envelope.max_file_name]u8 = @splat(0),
    name_len: usize = 0,
    size: u32 = 0,
    sha: [32]u8 = @splat(0),
    expected_seq: u32 = 0,
    buf: std.ArrayListUnmanaged(u8) = .empty,

    fn name(self: *const RxFile) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Обернуть TCP-коннект в fake-TLS (server-роль, accept-сторона).
fn faketlsServer(app: *App, tc: *tcp.TcpConn) !interfaces.Conn {
    const ft = shopot.net.faketls.wrap(app.alloc, app.io, tc.conn(), .server) catch |e| {
        return e;
    };
    {
        app.lock();
        defer app.unlock();
        app.ftlss.append(app.alloc, ft.ftls) catch {
            ft.ftls.deinit();
            app.alloc.destroy(ft.ftls);
            return error.OutOfMemory;
        };
    }
    return ft.conn;
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
    // транспортная маскировка под TLS: dialer = client-роль fake-TLS
    const ft = shopot.net.faketls.wrap(app.alloc, app.io, tc.conn(), .client) catch |e| {
        app.alloc.destroy(sc);
        return e;
    };
    {
        app.lock();
        defer app.unlock();
        app.ftlss.append(app.alloc, ft.ftls) catch {
            ft.ftls.deinit();
            app.alloc.destroy(ft.ftls);
            app.alloc.destroy(sc);
            return error.OutOfMemory;
        };
    }
    const s = session_mod.Session.establish(
        app.alloc,
        ft.conn,
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
    // держатель инвайта: JOIN — ПЕРВЫМ конвертом, до bind/PROFILE:
    // пир-сторона в pending-режиме закрывает соединение на любом конверте,
    // кроме JOIN
    sendJoinIfDue(app, cid, s);
    try app.bindSession(cid, s, sc);
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
        const raw = faketlsServer(app, tc) catch {
            app.alloc.destroy(sc);
            tc.deinit();
            continue;
        };
        const s = session_mod.Session.establish(
            app.alloc,
            raw,
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
    const oc = try app.eng.sendText(cid, body);
    persistMsg(app, cid, true, oc.msg_id, oc.result == .sent, app.nowMs(), body);
    if (oc.result == .queued) {
        persistOutboxAdd(app);
        var qb: [80]u8 = undefined;
        const t = std.fmt.bufPrint(&qb, "в очереди: доставлю, когда {s} появится", .{app.eng.contacts.items[@intCast(cid - 1)].getName()}) catch "в очереди";
        fb(app, @intCast(cid - 1), t);
    }
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &oc.msg_id) catch return;
    var lb: [64]u8 = undefined;
    const mt = std.fmt.bufPrint(&lb, "msg_id {s}", .{hx}) catch return;
    fb(app, @intCast(cid - 1), mt);
}

fn cmdReact(app: *App, args: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, args, " ");
    const id_str = it.next() orelse return error.BadArgs;
    const mid_hex = it.next() orelse return error.BadArgs;
    const code_str = it.next() orelse return error.BadArgs;
    const cid = try std.fmt.parseInt(i64, id_str, 10);
    const mid = try parseHex16(mid_hex);
    const code = try parseCodepoint(code_str);
    if (code > 0x10FFFF) return error.BadArgs;
    app.lock();
    defer app.unlock();
    try app.eng.react(cid, mid, envelope.react_add, code);
    persistReact(app, cid, true, mid, code, app.nowMs());
}

/// Unicode code point из аргумента: 100, 0x2764, U+2764, ❤ (сам глиф).
fn parseCodepoint(arg: []const u8) !u32 {
    if (arg.len == 0) return error.BadArgs;
    if (arg.len >= 2 and (std.mem.startsWith(u8, arg, "0x") or std.mem.startsWith(u8, arg, "0X")))
        return std.fmt.parseInt(u32, arg[2..], 16);
    if (arg.len >= 2 and (std.mem.startsWith(u8, arg, "U+") or std.mem.startsWith(u8, arg, "u+")))
        return std.fmt.parseInt(u32, arg[2..], 16);
    // односимвольная UTF-8 последовательность — её кодпоинт
    const len = std.unicode.utf8ByteSequenceLength(arg[0]) catch return std.fmt.parseInt(u32, arg, 10);
    if (len == arg.len) {
        return std.unicode.utf8Decode(arg) catch return error.BadArgs;
    }
    return std.fmt.parseInt(u32, arg, 10);
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

/// Записать реакцию в лог (kind react: [cid u16][flags u8][msg_id 16]
/// [code u32][ts u64]; бит0 flags = моя реакция).
fn persistReact(app: *App, cid: i64, mine: bool, msg_id: [16]u8, code: u32, ts_ms: i64) void {
    const log = app.log orelse return;
    var buf: [31]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    buf[2] = @intFromBool(mine);
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    std.mem.writeInt(u32, buf[19..23], code, .little);
    std.mem.writeInt(u64, buf[23..31], @intCast(ts_ms), .little);
    _ = log.append(.react, buf[0..31]) catch {};
}

/// Записать сообщение в историю (kind msg, шифрованный лог).
/// ts — реальное локальное время (мс), метка в конверте остаётся приватной.
fn persistMsg(app: *App, cid: i64, mine: bool, msg_id: [16]u8, delivered: bool, ts_ms: i64, body: []const u8) void {
    const log = app.log orelse return;
    if (body.len == 0 or body.len > 4096) return;
    var buf: [3 + 16 + 8 + 2 + 4096]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    // бит0 = mine, бит1 = delivered
    buf[2] = @as(u8, @intFromBool(mine)) | (@as(u8, @intFromBool(delivered)) << 1);
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    std.mem.writeInt(u64, buf[19..27], @intCast(ts_ms), .little);
    std.mem.writeInt(u16, buf[27..29], @intCast(body.len), .little);
    @memcpy(buf[29 .. 29 + body.len], body);
    _ = log.append(.msg, buf[0 .. 29 + body.len]) catch {};
}

/// Записать принятый файл в лог (kind file): переживает рестарты.
/// Вызывается под app.mu.
fn persistFileMeta(app: *App, cid: i64, file_id: [16]u8, size: u32, name: []const u8) void {
    const log = app.log orelse return;
    var buf: [23 + 64]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    @memcpy(buf[2..18], &file_id);
    std.mem.writeInt(u32, buf[18..22], size, .little);
    const n = @min(name.len, 64);
    buf[22] = @intCast(n);
    @memcpy(buf[23 .. 23 + n], name[0..n]);
    _ = log.append(.file, buf[0 .. 23 + n]) catch {};
}

/// setname <имя>: моё отображаемое имя (лог set:2 + PROFILE пир-ам онлайн).
fn cmdSetName(app: *App, args: []const u8) !void {
    const name = std.mem.trim(u8, args, " ");
    if (name.len == 0 or name.len > 32) return error.BadArgs;
    app.lock();
    defer app.unlock();
    app.eng.setMyProfile(name, app.eng.my_avatar_id);
    if (app.log) |log| {
        var nb: [33]u8 = undefined;
        nb[0] = 2;
        @memcpy(nb[1 .. 1 + name.len], name);
        _ = log.append(.set, nb[0 .. 1 + name.len]) catch {};
    }
    for (app.eng.contacts.items, 0..) |_, i| {
        const cid: i64 = @intCast(i + 1);
        if (app.eng.sessions.contains(cid)) {
            app.eng.sendProfile(cid) catch {};
        }
    }
    fb(app, null, "имя задано");
}

/// setavatar <путь>: задать мой аватар (кэш + лог set:1 + PROFILE пир-ам онлайн).
fn cmdSetAvatar(app: *App, args: []const u8) !void {
    const path = std.mem.trim(u8, args, " ");
    if (path.len == 0) return error.BadArgs;
    const f = std.Io.Dir.openFileAbsolute(app.io, path, .{ .mode = .read_only }) catch
        return error.FileNotFound;
    defer f.close(app.io);
    const data = app.alloc.alloc(u8, envelope.max_avatar_data) catch return error.OutOfMemory;
    defer app.alloc.free(data);
    const n = f.readPositionalAll(app.io, data, 0) catch return error.FileNotFound;
    const bytes = data[0..n];
    if (bytes.len == 0) return error.TooBig;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const id = digest[0..16].*;
    {
        app.lock();
        defer app.unlock();
        if (!app.avatars.contains(id)) {
            const copy = app.alloc.dupe(u8, bytes) catch return error.OutOfMemory;
            app.avatars.put(app.alloc, id, copy) catch return error.OutOfMemory;
        }
        app.eng.setMyProfile(app.eng.myName(), id);
        if (app.log) |log| {
            var rb: [17]u8 = undefined;
            rb[0] = 1;
            @memcpy(rb[1..17], &id);
            _ = log.append(.set, rb[0..17]) catch {};
        }
        // кэш байтов — тоже kind avatar, чтобы peer-REQ перекачивал и после рестарта
        if (app.log) |log| {
            var ab: [18 + 16000]u8 = undefined;
            @memcpy(ab[0..16], &id);
            std.mem.writeInt(u16, ab[16..18], @intCast(data.len), .little);
            @memcpy(ab[18 .. 18 + bytes.len], bytes);
            _ = log.append(.avatar, ab[0 .. 18 + bytes.len]) catch {};
        }
        // PROFILE всем онлайн-сессиям
        for (app.eng.contacts.items, 0..) |_, i| {
            const cid: i64 = @intCast(i + 1);
            if (app.eng.sessions.contains(cid)) {
                app.eng.sendProfile(cid) catch {};
            }
        }
    }
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &id) catch return;
    var line: [96]u8 = undefined;
    const t = std.fmt.bufPrint(&line, "аватар задан: {s} ({d} байт)", .{ hx, bytes.len }) catch return;
    fb(app, null, t);
}

/// sendfile <cid> <путь>: передача файла чанками FILE_META + FILE_DATA.
/// Чанк 16000 байт = один obf-кадр; file_id = SHA-256(файла)[0..16].
fn cmdSendFile(app: *App, args: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, args, " ");
    const id_str = it.next() orelse return error.BadArgs;
    const path = std.mem.trim(u8, it.rest(), " ");
    if (path.len == 0) return error.BadArgs;
    const cid = try std.fmt.parseInt(i64, id_str, 10);
    // только имя файла, без каталогов
    const base = if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| path[i + 1 ..] else path;
    if (base.len == 0 or base.len > envelope.max_file_name) return error.BadArgs;
    const f = std.Io.Dir.openFileAbsolute(app.io, path, .{ .mode = .read_only }) catch
        return error.FileNotFound;
    defer f.close(app.io);
    // лимит: 64 МБ (u32 размер + разумный таймаут перекачки)
    const max_file_total = 64 * 1024 * 1024;
    const data = app.alloc.alloc(u8, max_file_total) catch return error.OutOfMemory;
    defer app.alloc.free(data);
    const n = f.readPositionalAll(app.io, data, 0) catch return error.FileNotFound;
    if (n == 0 or n > std.math.maxInt(u32)) return error.TooBig;
    const bytes = data[0..n];
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const file_id = digest[0..16].*;
    {
        app.lock();
        defer app.unlock();
        try app.eng.sendFileMeta(cid, file_id, base, @intCast(n), digest);
        var seq: u32 = 0;
        var off: usize = 0;
        while (off < bytes.len) {
            const chunk_len = @min(bytes.len - off, envelope.max_file_chunk);
            try app.eng.sendFileChunk(cid, file_id, seq, bytes[off .. off + chunk_len]);
            off += chunk_len;
            seq += 1;
        }
    }
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &file_id) catch return;
    var line: [128]u8 = undefined;
    const t = std.fmt.bufPrint(&line, "файл отправлен: {s} ({d} байт, {d} чанк.)", .{ hx, n, @divTrunc(n + envelope.max_file_chunk - 1, envelope.max_file_chunk) }) catch return;
    fb(app, null, t);
}

/// avatar <cid>: id текущего аватара контакта (или "нет").
fn cmdAvatar(app: *App, args: []const u8) !void {
    const cid = try std.fmt.parseInt(i64, std.mem.trim(u8, args, " "), 10);
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return error.NoContact;
    const c = &app.eng.contacts.items[@intCast(cid - 1)];
    if (std.mem.eql(u8, &c.avatar_id, &@as([16]u8, @splat(0)))) {
        fb(app, @intCast(cid - 1), "нет аватара");
        return;
    }
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &c.avatar_id) catch return;
    var line: [64]u8 = undefined;
    const t = std.fmt.bufPrint(&line, "avatar {s}", .{hx}) catch return;
    fb(app, @intCast(cid - 1), t);
}

/// history <cid> [limit]: последние N сообщений контакта (по логу).
fn cmdGetHistory(app: *App, args: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, args, " ");
    const cid = try std.fmt.parseInt(i64, it.next() orelse return error.BadArgs, 10);
    const limit = it.next() orelse "50";
    const n = try std.fmt.parseInt(u32, limit, 10);
    {
        app.lock();
        defer app.unlock();
        if (cid < 1 or cid > app.eng.contacts.items.len) return error.NoContact;
    }
    const log = app.log orelse return;
    // записи: [cid u16][flags u8][msg_id 16][ts u64][len u16][body]
    const recs = log.readAll(.msg, app.alloc) catch return;
    defer {
        for (recs) |r| app.alloc.free(r);
        app.alloc.free(recs);
    }
    var total: usize = 0;
    var start: usize = recs.len; // индекс первой записи окна
    {
        var count: usize = 0;
        var i: usize = recs.len;
        while (i > 0) {
            i -= 1;
            const rec = recs[i];
            if (rec.len < 29) continue;
            if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
            total += 1;
            count += 1;
            if (count == n) {
                start = i;
                break;
            }
        }
        if (i == 0 and start == recs.len) start = 0;
    }
    var idx2 = start;
    while (idx2 < recs.len) : (idx2 += 1) {
        const rec = recs[idx2];
        if (rec.len < 29) continue;
        if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
        const flags = rec[2];
        const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
        const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
        const blen = std.mem.readInt(u16, rec[27..29], .little);
        if (rec.len < 29 + blen) continue;
        var hxb: [32]u8 = undefined;
        const hx = toHex(&hxb, &msg_id) catch continue;
        var line: [256]u8 = undefined;
        const t = std.fmt.bufPrint(&line, "msg {s} {s} {d} {s}", .{
            if (flags & 1 != 0) "mine" else "theirs",
            hx,
            ts_ms,
            rec[29 .. 29 + blen],
        }) catch continue;
        fb(app, @intCast(cid - 1), t);
    }
    var fin: [48]u8 = undefined;
    const f = std.fmt.bufPrint(&fin, "hist_end {d} {d}", .{ cid, total }) catch return;
    fb(app, null, f);
}

/// getmessage <msg_id_hex>: одно сообщение по идентификатору.
fn cmdGetMessage(app: *App, args: []const u8) !void {
    const trimmed = std.mem.trim(u8, args, " ");
    if (trimmed.len == 0) return error.BadArgs;
    const want = try parseHex16(trimmed);
    const log = app.log orelse return;
    const recs = log.readAll(.msg, app.alloc) catch return;
    defer {
        for (recs) |r| app.alloc.free(r);
        app.alloc.free(recs);
    }
    var last: ?[]u8 = null;
    for (recs) |rec| {
        if (rec.len < 29) continue;
        if (!std.mem.eql(u8, rec[3 .. 3 + 16], &want)) continue;
        last = rec;
    }
    const rec = last orelse {
        // "!" — маркер ошибки: тег @<n> ответит err
        fb(app, null, "! не найдено");
        return;
    };
    const flags = rec[2];
    const cid = std.mem.readInt(u16, rec[0..2], .little);
    const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
    const blen = std.mem.readInt(u16, rec[27..29], .little);
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &want) catch return;
    var line: [256]u8 = undefined;
    const t = std.fmt.bufPrint(&line, "msg {s} {d} {s} {d} {s}", .{
        if (flags & 1 != 0) "mine" else "theirs",
        cid,
        hx,
        ts_ms,
        rec[29..@min(29 + blen, rec.len)],
    }) catch return;
    fb(app, null, t);
    // реакции на это сообщение: react <mine|theirs> <codepoint> <ts_ms>
    const rrecs = log.readAll(.react, app.alloc) catch return;
    defer {
        for (rrecs) |rr| app.alloc.free(rr);
        app.alloc.free(rrecs);
    }
    for (rrecs) |rr| {
        if (rr.len < 31) continue;
        if (!std.mem.eql(u8, rr[3 .. 3 + 16], &want)) continue;
        const rflags = rr[2];
        const rcode = std.mem.readInt(u32, rr[19..23], .little);
        const rts = std.mem.readInt(u64, rr[23..31], .little);
        var rl: [64]u8 = undefined;
        const rt = std.fmt.bufPrint(&rl, "react {s} {d} {d}", .{
            if (rflags & 1 != 0) "mine" else "theirs",
            rcode,
            rts,
        }) catch continue;
        fb(app, null, rt);
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
    // аватары: кэш id -> байты (свои и чужие)
    const avs = log.readAll(.avatar, app.alloc) catch return;
    defer {
        for (avs) |r| app.alloc.free(r);
        app.alloc.free(avs);
    }
    for (avs) |rec| {
        if (rec.len < 18) continue;
        const alen = std.mem.readInt(u16, rec[16..18], .little);
        if (alen == 0 or alen > 16000 or rec.len < 18 + alen) continue;
        const id: [16]u8 = rec[0..16].*;
        const copy = app.alloc.dupe(u8, rec[18 .. 18 + alen]) catch continue;
        app.avatars.put(app.alloc, id, copy) catch {
            app.alloc.free(copy);
        };
    }
    // свой профиль: set:1 = avatar_id
    const sets = log.readAll(.set, app.alloc) catch return;
    defer {
        for (sets) |r| app.alloc.free(r);
        app.alloc.free(sets);
    }
    for (sets) |rec| {
        if (rec.len == 17 and rec[0] == 1) app.eng.my_avatar_id = rec[1..17].*;
        if (rec.len >= 2 and rec[0] == 2) app.eng.setMyProfile(rec[1..rec.len], app.eng.my_avatar_id);
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

/// Ответ на команду: уходит подключённому UDS-клиенту (cli_out), иначе — в лог демона.
fn fb(app: *App, idx: ?usize, txt: []const u8) void {
    // UDS-клиент ждёт ответа команды — отдаём ему, а не в лог демона
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

/// Исполнение команды UDS-апи (возвращает false для выхода).
pub fn execCmd(app: *App, trimmed: []const u8) bool {
    var errbuf: [96]u8 = undefined;
    var it = std.mem.tokenizeAny(u8, trimmed, " ");
    const cmd = it.next() orelse return true;
    const rest = std.mem.trim(u8, trimmed[cmd.len..], " ");

    if (std.mem.eql(u8, cmd, "help")) {
        fb(app, null, "invite <имя> · add <код|hex> · msg <id> <текст> · react <id> <msg_id> <U+код> · block/unblock <id>");
        fb(app, null, "sendfile <id> <путь> · gethistory <id> [n] · getmessage <msg_id> · call <id> · answer · hangup · contacts · connect · listen · quit");
    } else if (std.mem.eql(u8, cmd, "quit") or std.mem.eql(u8, cmd, "q")) {
        app.running = false;
    } else if (std.mem.eql(u8, cmd, "contacts")) {
        cmdContacts(app, rest);
    } else if (std.mem.eql(u8, cmd, "id")) {
        cmdId(app);
    } else if (std.mem.eql(u8, cmd, "invite")) {
        cmdInvite(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "приглашение", e));
    } else if (std.mem.eql(u8, cmd, "add")) {
        cmdAdd(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "add", e));
    } else if (std.mem.eql(u8, cmd, "msg")) {
        cmdMsg(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "msg", e));
    } else if (std.mem.eql(u8, cmd, "react")) {
        cmdReact(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "react", e));
    } else if (std.mem.eql(u8, cmd, "setname")) {
        cmdSetName(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "setname", e));
    } else if (std.mem.eql(u8, cmd, "setavatar")) {
        cmdSetAvatar(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "setavatar", e));
    } else if (std.mem.eql(u8, cmd, "sendfile")) {
        cmdSendFile(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "sendfile", e));
    } else if (std.mem.eql(u8, cmd, "avatar")) {
        cmdAvatar(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "avatar", e));
    } else if (std.mem.eql(u8, cmd, "gethistory") or std.mem.eql(u8, cmd, "history")) {
        cmdGetHistory(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "gethistory", e));
    } else if (std.mem.eql(u8, cmd, "getmessage")) {
        cmdGetMessage(app, rest) catch |e| fb(app, null, fmtErr(&errbuf, "getmessage", e));
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

    if (std.mem.eql(u8, cmd, "serve")) {
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

        // буфер переписки по контактам: heap-массив (стеку 12+ МБ не отдавать)
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
            .home_len = @min(home.len, app_home_max),
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *SessCtx).init(alloc),
            .call_pcm_dir = if (pcm_heap.len > 0) pcm_heap else null,
            .threads = threads,
            .tz = tui_mod.tzOffset(),
        };
        @memcpy(app.home_buf[0..app.home_len], home[0..app.home_len]);
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

        // Единственный интерфейс: UDS-апи для клиентов
        cli_srv.start(&app, home);
        std.debug.print("serve: демон работает, UDS-апи готово\n", .{});
        while (app.running) {
            const req: std.os.linux.timespec = .{ .sec = 1, .nsec = 0 };
            _ = std.os.linux.nanosleep(&req, null);
        }

        eng.deinit();
        return;
    }

    std.debug.print("{s}\n", .{usage});
}
