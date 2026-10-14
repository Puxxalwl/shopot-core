//! CLI-сервер: UDS-апи поверх одного ядра shopot.
//!
//! Сокет $HOME/.shopot/api.sock, построчный протокол (без JSON, как весь
//! проект): команды те же, что в REPL/TUI — msg/call/answer/hangup/block/
//! unblock/contacts/help... Голый текст = сообщение в выбранный чат.
//! Ответы на команды — произвольные строки (те же тексты, что видит TUI).
//! События ядра приходят строками с префиксами:
//!   msg <cid> <имя> <текст>   — входящее сообщение
//!   sys <cid> <текст>         — служебная строка (звонки, presence)
//!   presence <cid> on|off     — контакт на связи / пропал
//! quit — закрыть соединение (не демон).
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const main = @import("main.zig");

/// Максимум одной строки протокола (как REPL).
pub const max_line = 2048;

fn cut(s: []const u8, n: usize) []const u8 {
    return s[0..@min(s.len, n)];
}

/// Запись в fd (linux-сисколл, как net/tcp.zig). Возвращает записанные байты.
fn rawWrite(fd: posix.socket_t, bytes: []const u8) usize {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        const e = linux.errno(rc);
        if (e == .INTR) continue;
        if (e != .SUCCESS) return off;
        off += @intCast(rc);
    }
    return off;
}

/// Чтение из fd. null — ошибка или EOF (соединение закрыто).
fn rawRead(fd: posix.socket_t, buf: []u8) ?usize {
    while (true) {
        const rc = linux.read(fd, buf.ptr, buf.len);
        const e = linux.errno(rc);
        if (e == .INTR) continue;
        if (e != .SUCCESS) return null;
        return @intCast(rc);
    }
}

pub const Conn = struct {
    fd: posix.socket_t,
    srv: *Server,
    /// Сериализует записи в сокет (ответы из fb + события из движка).
    /// Спин-блок: запись микросекундная, конкурентов мало.
    wmu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn sendRaw(self: *Conn, bytes: []const u8) void {
        while (self.wmu.swap(true, .acquire)) std.Thread.yield() catch {};
        defer self.wmu.store(false, .release);
        _ = rawWrite(self.fd, bytes);
    }

    /// Строка-ответ на команду (приходит из fb).
    pub fn writeText(self: *Conn, txt: []const u8) void {
        var buf: [max_line + 16]u8 = undefined;
        const t = std.fmt.bufPrint(&buf, "{s}\n", .{cut(txt, max_line)}) catch return;
        self.sendRaw(t);
    }

    /// Событие: входящее сообщение контакта.
    pub fn evMsg(self: *Conn, cid: i64, name: []const u8, body: []const u8) void {
        var buf: [max_line + 16]u8 = undefined;
        const t = std.fmt.bufPrint(&buf, "msg {d} {s} {s}\n", .{ cid, cut(name, 31), cut(body, max_line - 48) }) catch return;
        self.sendRaw(t);
    }

    /// Событие: служебная строка (звонки, presence-перемены).
    pub fn evSys(self: *Conn, cid: i64, body: []const u8) void {
        var buf: [256]u8 = undefined;
        const t = std.fmt.bufPrint(&buf, "sys {d} {s}\n", .{ cid, cut(body, 220) }) catch return;
        self.sendRaw(t);
    }

    /// Событие: контакт на связи / пропал.
    pub fn evPresence(self: *Conn, cid: i64, online: bool) void {
        var buf: [96]u8 = undefined;
        const t = std.fmt.bufPrint(&buf, "presence {d} {s}\n", .{ cid, if (online) "on" else "off" }) catch return;
        self.sendRaw(t);
    }
};

pub const Server = struct {
    app: *main.App,
    /// Подключённые CLI-клиенты. Список — под app.mu.
    conns: std.ArrayListUnmanaged(*Conn) = .empty,

    fn addConn(self: *Server, c: *Conn) void {
        const app = self.app;
        app.lock();
        defer app.unlock();
        self.conns.append(app.alloc, c) catch {};
    }

    fn removeConn(self: *Server, c: *Conn) void {
        const app = self.app;
        {
            app.lock();
            defer app.unlock();
            for (self.conns.items, 0..) |it, i| {
                if (it == c) {
                    _ = self.conns.swapRemove(i);
                    break;
                }
            }
        }
        // conn мог быть текущим приёмником fb — сбрасываем под cli_mu
        app.cliLock();
        if (app.cli_out == c) app.cli_out = null;
        app.cliUnlock();
        _ = linux.close(c.fd);
        app.alloc.destroy(c);
    }
};

/// Разослать событие всем CLI-клиентам (ВЫЗЫВАТЬ ПОД app.mu).
pub fn fanoutMsgLocked(app: *main.App, cid: i64, name: []const u8, body: []const u8) void {
    const srv = app.cli orelse return;
    for (srv.conns.items) |c| c.evMsg(cid, name, body);
}

/// Служебная строка всем CLI-клиентам (ВЫЗЫВАТЬ ПОД app.mu).
pub fn fanoutSysLocked(app: *main.App, cid: i64, name: []const u8, body: []const u8) void {
    _ = name; // имя не нужно UDS-событию sys <cid> <текст>
    const srv = app.cli orelse return;
    for (srv.conns.items) |c| c.evSys(cid, body);
}

/// Presence-перемена всем CLI-клиентам (ВЫЗЫВАТЬ ПОД app.mu).
pub fn fanoutPresenceLocked(app: *main.App, cid: i64, name: []const u8, online: bool) void {
    _ = name;
    const srv = app.cli orelse return;
    for (srv.conns.items) |c| c.evPresence(cid, online);
}

/// Выполнить команду ядра с перенаправлением ответов fb в соединение.
/// execCmd сам управляет локом app.mu — здесь лок НЕ держим.
fn runCmd(app: *main.App, conn: *Conn, cmd: []const u8) void {
    app.cliLock();
    app.cli_out = conn;
    app.cliUnlock();
    defer {
        app.cliLock();
        app.cli_out = null;
        app.cliUnlock();
    }
    _ = main.execCmd(app, cmd);
}

/// cid выбранного чата (общий с TUI выбор).
fn selectedCid(app: *main.App) ?i64 {
    app.lock();
    defer app.unlock();
    const n = app.eng.contacts.items.len;
    if (n == 0) return null;
    return @intCast(@min(app.sel, n - 1) + 1);
}

const known_cmds = [_][]const u8{
    "help", "contacts", "invite", "add",     "msg",    "react", "block", "unblock",
    "call", "answer",   "hangup", "connect", "listen",
};

fn isKnownCmd(word: []const u8) bool {
    for (known_cmds) |k| {
        if (std.mem.eql(u8, k, word)) return true;
    }
    return false;
}

/// Одна строка UDS-апи. Возвращает false — закрыть соединение.
fn handleUdsLine(srv: *Server, conn: *Conn, line: []const u8) bool {
    const app = srv.app;
    if (line.len == 0) return true;
    var it = std.mem.tokenizeAny(u8, line, " ");
    const first = it.next() orelse return true;
    if (std.mem.eql(u8, first, "quit") or std.mem.eql(u8, first, "q")) {
        conn.writeText("bye");
        return false;
    }
    if (isKnownCmd(first)) {
        runCmd(app, conn, line);
        return true;
    }
    // голый текст — сообщение в выбранный чат
    const cid = selectedCid(app) orelse {
        conn.writeText("! нет контактов — add <код> сначала");
        return true;
    };
    var buf: [max_line]u8 = undefined;
    const t = std.fmt.bufPrint(&buf, "msg {d} {s}", .{ cid, cut(line, max_line - 24) }) catch return true;
    runCmd(app, conn, t);
    return true;
}

/// Поток одного CLI-клиента: читает, разбирает, исполняет.
fn connLoop(srv: *Server, conn: *Conn) void {
    const app = srv.app;
    var rbuf: [1024]u8 = undefined;
    var acc: [max_line]u8 = undefined;
    var acc_len: usize = 0;
    outer: while (app.running) {
        const n = rawRead(conn.fd, &rbuf) orelse break;
        if (n == 0) break;
        const data = rbuf[0..n];
        // UDS: построчно, хвост без \n копится
        var pos: usize = 0;
        while (pos < data.len) {
            const rest = data[pos..];
            const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse {
                const add = @min(rest.len, acc.len - acc_len);
                @memcpy(acc[acc_len..][0..add], rest[0..add]);
                acc_len += add;
                break;
            };
            var lbuf: [max_line]u8 = undefined;
            var line: []const u8 = rest[0..nl];
            if (acc_len > 0) {
                const joined_len = @min(acc_len + line.len, lbuf.len);
                @memcpy(lbuf[0..@min(acc_len, joined_len)], acc[0..@min(acc_len, joined_len)]);
                const rest_len = joined_len - @min(acc_len, joined_len);
                @memcpy(lbuf[@min(acc_len, joined_len)..][0..rest_len], line[0..rest_len]);
                line = lbuf[0..joined_len];
                acc_len = 0;
            }
            if (!handleUdsLine(srv, conn, line)) break :outer;
            pos += nl + 1;
        }
    }
    srv.removeConn(conn);
}

fn spawnConn(srv: *Server, fd: posix.socket_t) void {
    const app = srv.app;
    const c = app.alloc.create(Conn) catch {
        _ = linux.close(fd);
        return;
    };
    c.* = .{ .fd = fd, .srv = srv };
    srv.addConn(c);
    const th = std.Thread.spawn(.{}, struct {
        fn go(s: *Server, cc: *Conn) void {
            connLoop(s, cc);
        }
    }.go, .{ srv, c }) catch {
        srv.removeConn(c);
        return;
    };
    th.detach();
}

fn udsAcceptLoop(srv: *Server, lfd: posix.socket_t) void {
    while (srv.app.running) {
        const rc = linux.accept4(lfd, null, null, 0);
        if (linux.errno(rc) != .SUCCESS) continue;
        spawnConn(srv, @intCast(rc));
    }
}

/// Поднять CLI-сервер: UDS-сокет $HOME/.shopot/api.sock.
/// Вызывается один раз при старте chat/serve (до старта потоков фронт-енда).
pub fn start(app: *main.App, home: []const u8) void {
    if (home.len == 0) return;
    const srv = app.alloc.create(Server) catch return;
    srv.* = .{ .app = app };
    app.cli = srv;

    // --- UDS: $HOME/.shopot/api.sock ---
    var pb: [128]u8 = undefined;
    const sock_path = std.fmt.bufPrint(&pb, "{s}/.shopot/api.sock", .{home}) catch return;
    std.Io.Dir.deleteFileAbsolute(app.io, sock_path) catch {};
    const ufd_rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
    if (linux.errno(ufd_rc) != .SUCCESS) {
        std.debug.print("cli-апи: uds-сокет не создан\n", .{});
        return;
    }
    const ufd: posix.socket_t = @intCast(ufd_rc);
    {
        var ua = linux.sockaddr.un{ .family = linux.AF.UNIX, .path = @splat(0) };
        const plen = @min(sock_path.len, ua.path.len - 1);
        @memcpy(ua.path[0..plen], sock_path[0..plen]);
        const brc = linux.bind(ufd, @ptrCast(&ua), @sizeOf(linux.sockaddr.un));
        if (linux.errno(brc) != .SUCCESS) {
            std.debug.print("cli-апи: bind {s} не удался\n", .{sock_path});
            _ = linux.close(ufd);
            return;
        }
    }
    {
        const lrc = linux.listen(ufd, 8);
        if (linux.errno(lrc) != .SUCCESS) {
            _ = linux.close(ufd);
            return;
        }
    }
    const ut = std.Thread.spawn(.{}, struct {
        fn go(s: *Server, fd: posix.socket_t) void {
            udsAcceptLoop(s, fd);
        }
    }.go, .{ srv, ufd }) catch {
        _ = linux.close(ufd);
        return;
    };
    ut.detach();
    std.debug.print("cli-апи: uds {s}\n", .{sock_path});
}
