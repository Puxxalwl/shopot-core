//! UDS-сервер бинарного API — единственный интерфейс ядра shopot для GUI.
//!
//! Сокет $HOME/.shopot/api.sock (0700). Протокол — бинарные кадры (api.zig,
//! полная спецификация — docs/CORE-API.md): запрос клиента → ровно один
//! ответ ядра с корреляцией по request_id; события ядра рассылаются всем
//! подключённым клиентам. Строк на проводе нет.
//!
//! Потоки: по одному на соединение (команды исполняются последовательно
//! под app.mu, как раньше). Запись в сокет сериализуется спин-локом wmu:
//! ответы из потока команды и события из потоков сессий не перемешиваются.
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const main = @import("main.zig");
const api = @import("api.zig");

/// Размер буфера чтения сокета. 64 KiB снижает syscall overhead на больших
/// ответах, не меняя потоковый формат API.
const read_chunk = 64 * 1024;

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

/// Одно соединение GUI-клиента.
pub const Conn = struct {
    fd: posix.socket_t,
    srv: *Server,
    /// Сериализует записи в сокет (ответы из fb + события из движка).
    /// Спин-блок: запись микросекундная, конкурентов мало.
    wmu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    // ---- накопление текущего кадра (TCP/UDS отдаёт байты порциями) ----
    hdr_acc: [api.header_len]u8 = @splat(0),
    hdr_have: usize = 0,
    /// Заголовок кадра, чей payload читается.
    cur_hdr: api.Header = .{ .kind = .request, .id = 0, .request_id = 0, .status = .OK, .payload_len = 0 },
    /// Payload текущего запроса (аллоцирован по длине заголовка).
    payload: ?[]u8 = null,
    payload_have: usize = 0,

    /// Записать кадр целиком (заголовок + payload) под wmu.
    fn sendFrame(self: *Conn, hdr: api.Header, payload: []const u8) void {
        var hbuf: [api.header_len]u8 = undefined;
        api.encodeHeader(&hbuf, hdr);
        while (self.wmu.swap(true, .acquire)) std.Thread.yield() catch {};
        defer self.wmu.store(false, .release);
        _ = rawWrite(self.fd, &hbuf);
        if (payload.len > 0) _ = rawWrite(self.fd, payload);
    }

    /// Ответ на запрос: method_id/request_id повторяются из запроса.
    /// method_id — сырой id метода (в т.ч. неизвестный ядру).
    pub fn sendResponse(self: *Conn, method_id: u16, request_id: u32, status: api.Status, payload: []const u8) void {
        self.sendFrame(.{
            .kind = .response,
            .id = method_id,
            .request_id = request_id,
            .status = status,
            .payload_len = @intCast(payload.len),
        }, payload);
    }

    /// Событие ядра (без request_id).
    pub fn sendEvent(self: *Conn, ev: api.Event, payload: []const u8) void {
        self.sendFrame(.{
            .kind = .event,
            .id = @backingInt(ev),
            .request_id = 0,
            .status = .OK,
            .payload_len = @intCast(payload.len),
        }, payload);
    }
};

pub const Server = struct {
    app: *main.App,
    /// Подключённые клиенты. Список — под app.mu.
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
        if (c.payload) |p| app.alloc.free(p);
        _ = linux.close(c.fd);
        app.alloc.destroy(c);
    }
};

/// Разослать событие всем клиентам (ВЫЗЫВАТЬ ПОД app.mu).
pub fn fanoutEventLocked(app: *main.App, ev: api.Event, payload: []const u8) void {
    const srv = app.cli orelse return;
    for (srv.conns.items) |c| c.sendEvent(ev, payload);
}

/// Обработка одного собранного кадра-запроса. false — закрыть соединение.
fn handleFrame(srv: *Server, conn: *Conn, hdr: api.Header, payload: []const u8) bool {
    if (hdr.kind != .request) {
        // протокол нарушен: синхронизация потока потеряна — закрываем
        conn.sendResponse(hdr.id, hdr.request_id, .BAD_FRAME, &.{});
        return false;
    }
    const method = std.enums.fromInt(api.Method, hdr.id) orelse {
        conn.sendResponse(hdr.id, hdr.request_id, .UNKNOWN_METHOD, &.{});
        return true;
    };
    return main.dispatchApi(srv.app, conn, .{
        .method = method,
        .request_id = hdr.request_id,
        .payload = payload,
    });
}

/// Скармливает байты конечному автомату кадра. false — закрыть соединение.
fn feed(srv: *Server, conn: *Conn, data: []const u8) bool {
    var pos: usize = 0;
    while (pos < data.len) {
        // 1) заголовок
        if (conn.hdr_have < api.header_len) {
            const need = api.header_len - conn.hdr_have;
            const add = @min(need, data.len - pos);
            @memcpy(conn.hdr_acc[conn.hdr_have..][0..add], data[pos..][0..add]);
            conn.hdr_have += add;
            pos += add;
            if (conn.hdr_have < api.header_len) return true;
            const hdr = api.decodeHeader(&conn.hdr_acc) orelse {
                conn.sendResponse(0, 0, .BAD_FRAME, &.{});
                return false;
            };
            if (hdr.payload_len > api.max_payload) {
                conn.sendResponse(hdr.id, hdr.request_id, .TOO_BIG, &.{});
                return false;
            }
            if (hdr.payload_len > 0) {
                conn.payload = srv.app.alloc.alloc(u8, hdr.payload_len) catch {
                    conn.sendResponse(hdr.id, hdr.request_id, .INTERNAL, &.{});
                    return false;
                };
                conn.payload_have = 0;
            }
            conn.cur_hdr = hdr;
        }
        // 2) payload
        if (conn.payload) |p| {
            const need = p.len - conn.payload_have;
            const add = @min(need, data.len - pos);
            @memcpy(p[conn.payload_have..][0..add], data[pos..][0..add]);
            conn.payload_have += add;
            pos += add;
            if (conn.payload_have < p.len) return true;
        }
        // 3) кадр собран: исполнить и освободить payload
        const hdr = conn.cur_hdr;
        const pbuf = conn.payload;
        conn.hdr_have = 0;
        conn.payload = null;
        conn.payload_have = 0;
        const ok = handleFrame(srv, conn, hdr, if (pbuf) |p| p else &.{});
        if (pbuf) |p| srv.app.alloc.free(p);
        if (!ok) return false;
    }
    return true;
}

/// Поток одного клиента: читает байты, собирает кадры, исполняет.
fn connLoop(srv: *Server, conn: *Conn) void {
    const app = srv.app;
    var rbuf: [read_chunk]u8 = undefined;
    while (app.running) {
        const n = rawRead(conn.fd, &rbuf) orelse break;
        if (n == 0) break;
        if (!feed(srv, conn, rbuf[0..n])) break;
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

/// Поднять API-сервер: UDS-сокет $HOME/.shopot/api.sock.
/// Вызывается один раз при старте serve (до старта потоков фронт-енда).
pub fn start(app: *main.App, home: []const u8) void {
    if (home.len == 0) return;
    const srv = app.alloc.create(Server) catch return;
    srv.* = .{ .app = app };
    app.cli = srv;

    var pb: [128]u8 = undefined;
    const sock_path = std.fmt.bufPrint(&pb, "{s}/.shopot/api.sock", .{home}) catch return;
    std.Io.Dir.deleteFileAbsolute(app.io, sock_path) catch {};
    const ufd_rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
    if (linux.errno(ufd_rc) != .SUCCESS) {
        std.debug.print("api: uds-сокет не создан\n", .{});
        return;
    }
    const ufd: posix.socket_t = @intCast(ufd_rc);
    {
        var ua = linux.sockaddr.un{ .family = linux.AF.UNIX, .path = @splat(0) };
        const plen = @min(sock_path.len, ua.path.len - 1);
        @memcpy(ua.path[0..plen], sock_path[0..plen]);
        const brc = linux.bind(ufd, @ptrCast(&ua), @sizeOf(linux.sockaddr.un));
        if (linux.errno(brc) != .SUCCESS) {
            std.debug.print("api: bind {s} не удался\n", .{sock_path});
            _ = linux.close(ufd);
            return;
        }
    }
    // сокет только владельцу: UDS-права не наследуют umask автоматически
    {
        var zbuf: [128]u8 = @splat(0);
        const zlen = @min(sock_path.len, zbuf.len - 1);
        @memcpy(zbuf[0..zlen], sock_path[0..zlen]);
        const crc = linux.fchmodat(linux.AT.FDCWD, @ptrCast(&zbuf), 0o700);
        _ = linux.errno(crc);
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
    std.debug.print("api: uds {s}\n", .{sock_path});
}
