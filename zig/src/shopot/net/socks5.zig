//! SOCKS5-клиент (RFC 1928) для use_tor_mask: исходящие прямые dial
//! уходят через локальный Tor-демон (127.0.0.1:9050) — пир видит IP
//! exit-узла, а не наш. Поддерживается ТОЛЬКО метод «без аутентификации»
//! (0x00): Tor его принимает; имя пользователя/пароли — вне рамок.
//!
//! Замечание о байтовом порядке: сам SOCKS5 — внешний протокол, порт в нём
//! big-endian (сетевой порядок); это осознанное исключение из общего
//! правила little-endian, действующего для внутренних форматов shopot.
//!
//! После CONNECT-фазы сокет — обычный байтовый туннель; возвращается
//! штатный TcpConn, дальнейшие слои (fake-TLS, обфускация, рукопожатие)
//! не подозревают о SOCKS.
const std = @import("std");
const tcp = @import("tcp.zig");
const linux = std.os.linux;

/// Ошибки SOCKS5-фазы (dial TCP поверх них — свои).
pub const SocksError = error{
    /// Адрес прокси/цели не разобран.
    BadAddress,
    /// Прокси закрыл соединение в рукопожатии.
    Closed,
    /// Сетевая ошибка.
    Network,
    /// Прокси требует аутентификацию (метод, отличный от 0x00).
    AuthRequired,
    /// Прокси отказал в CONNECT (код ответа != 0).
    Refused,
    OutOfMemory,
};

/// Версия протокола SOCKS.
const ver: u8 = 5;
/// ATYP: доменное имя (Tor предпочитает именно его — exit сам резолвит).
const atyp_domain: u8 = 0x03;

/// Greeting: [05 01 00] — «говорим SOCKS5, метод без аутентификации».
const greeting = [3]u8{ ver, 0x01, 0x00 };

/// Собрать CONNECT-запрос: [05 01 00 03 len host port BE].
/// host — домен или IPv4-литерал (≤ 255 байтов), port 1..65535.
/// Возвращает срез buf.
pub fn connectRequest(buf: []u8, host: []const u8, port: u16) SocksError![]const u8 {
    if (host.len == 0 or host.len > 255) return error.BadAddress;
    if (port == 0) return error.BadAddress;
    if (buf.len < 4 + 1 + host.len + 2) return error.BadAddress; // буфер мал (не сеть)
    var n: usize = 0;
    buf[0] = ver;
    buf[1] = 0x01; // CONNECT
    buf[2] = 0x00; // reserved
    buf[3] = atyp_domain;
    buf[4] = @intCast(host.len);
    n = 5;
    @memcpy(buf[n..][0..host.len], host);
    n += host.len;
    // SOCKS5: порт big-endian (сетевой порядок)
    std.mem.writeInt(u16, buf[n..][0..2], port, .big);
    n += 2;
    return buf[0..n];
}

/// Разобрать ПОЛНЫЙ ответ CONNECT ([05 rep 00 atyp][addr][port BE]):
/// rep != 0 — Refused; atyp 0x01/0x03/0x04 — допустимы (IPv4/домен/IPv6),
/// прочее — BadAddress. Ответ прокси нас не интересует содержательно
/// (bnd.addr — адрес, к которому прокси подключился с нашей стороны),
/// но обязан быть структурно валидным.
pub fn interpretReply(reply: []const u8) SocksError!void {
    if (reply.len < 4 + 2) return error.Closed;
    if (reply[0] != ver) return error.BadAddress;
    if (reply[1] != 0) return error.Refused;
    const atyp = reply[3];
    const addr_len: usize = switch (atyp) {
        0x01 => 4,
        0x03 => blk: {
            if (reply.len < 5) return error.Closed;
            // +1: байт длины имени идёт перед самим именем
            break :blk @as(usize, reply[4]) + 1;
        },
        0x04 => 16,
        else => return error.BadAddress,
    };
    if (reply.len != 4 + addr_len + 2) return error.Closed;
}

/// Dial через SOCKS5: proxy_addr и target — «host:port» (IPv4-литералы;
/// цель может быть доменом, Tor резолвит сам). Успех — готовый TcpConn,
/// туннелирующий байты до target.
pub fn dial(alloc: std.mem.Allocator, proxy_addr: []const u8, target_addr: []const u8) SocksError!*tcp.TcpConn {
    // цель: host + port
    const tcolon = std.mem.lastIndexOfScalar(u8, target_addr, ':') orelse return error.BadAddress;
    const host = target_addr[0..tcolon];
    const port = std.fmt.parseInt(u16, target_addr[tcolon + 1 ..], 10) catch return error.BadAddress;
    if (host.len == 0) return error.BadAddress;

    const tc = tcp.dial(alloc, proxy_addr) catch |e| return switch (e) {
        error.BadAddress => error.BadAddress,
        error.Network => error.Network,
        error.OutOfMemory => error.OutOfMemory,
    };
    errdefer {
        tc.deinit();
        alloc.destroy(tc);
    }

    // 1) greeting -> выбор метода
    rawWriteAll(tc.fd, &greeting) catch return error.Network;
    var method: [2]u8 = undefined;
    rawReadAll(tc.fd, &method) catch return error.Closed;
    if (method[0] != ver) return error.BadAddress;
    if (method[1] != 0x00) return error.AuthRequired;

    // 2) CONNECT -> ответ
    var req: [4 + 1 + 255 + 2]u8 = undefined;
    const creq = try connectRequest(&req, host, port);
    rawWriteAll(tc.fd, creq) catch return error.Network;

    // заголовок ответа: [ver rep rsv atyp]
    var hdr: [4]u8 = undefined;
    rawReadAll(tc.fd, &hdr) catch return error.Closed;
    if (hdr[0] != ver) return error.BadAddress;
    if (hdr[1] != 0) return error.Refused;
    const atyp = hdr[3];
    const addr_len: usize = switch (atyp) {
        0x01 => 4,
        0x03 => blk: {
            var l: [1]u8 = undefined;
            rawReadAll(tc.fd, &l) catch return error.Closed;
            break :blk l[0];
        },
        0x04 => 16,
        else => return error.BadAddress,
    };
    var rest: [16 + 2]u8 = undefined;
    rawReadAll(tc.fd, rest[0 .. addr_len + 2]) catch return error.Closed;

    return tc;
}

fn rawReadAll(fd: linux.socket_t, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        const rc = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (linux.errno(rc) != .SUCCESS) return error.Network;
        if (rc == 0) return error.Closed;
        got += @intCast(rc);
    }
}

fn rawWriteAll(fd: linux.socket_t, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(fd, bytes[sent..].ptr, bytes.len - sent);
        if (linux.errno(rc) != .SUCCESS) return error.Network;
        if (rc == 0) return error.Network;
        sent += @intCast(rc);
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

const testing = std.testing;

test "connectRequest: раскладка (порт big-endian)" {
    var buf: [4 + 1 + 255 + 2]u8 = undefined;
    const req = try connectRequest(&buf, "example.com", 0x1234);
    try testing.expectEqualSlices(u8, &.{
        0x05, 0x01, 0x00, 0x03, 11, // ver, CONNECT, rsv, ATYP=домен, длина
        'e',  'x',  'a',  'm',  'p',
        'l',  'e',  '.',  'c',  'o',
        'm',
        0x12, 0x34, // порт big-endian — исключение из LE-правила проекта
    }, req);
}

test "connectRequest: лимиты" {
    var buf: [4 + 1 + 255 + 2]u8 = undefined;
    // пустой хост
    try testing.expectError(error.BadAddress, connectRequest(&buf, "", 80));
    // порт 0
    try testing.expectError(error.BadAddress, connectRequest(&buf, "host", 0));
    // хост > 255
    var long_buf: [256]u8 = @splat('a');
    const long = long_buf[0..];
    try testing.expectError(error.BadAddress, connectRequest(&buf, long, 80));
}

test "interpretReply: валидные atyp" {
    // IPv4: [05 00 00 01][4 байта][2 байта порт]
    try interpretReply(&.{ 0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50 });
    // домен: [05 00 00 03][len][имя][порт]
    try interpretReply(&.{ 0x05, 0x00, 0x00, 0x03, 4, 'a', 'b', 'c', 'd', 0x00, 0x50 });
    // IPv6: [05 00 00 04][16 байтов][порт]
    var v6: [22]u8 = @splat(0);
    v6[0] = 0x05;
    v6[3] = 0x04;
    v6[20] = 0x00;
    v6[21] = 0x50;
    try interpretReply(v6[0..]);
}

test "interpretReply: отказы и мусор" {
    // rep != 0 (0x05 = соединение отклонено)
    try testing.expectError(error.Refused, interpretReply(&.{ 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }));
    // чужая версия
    try testing.expectError(error.BadAddress, interpretReply(&.{ 0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }));
    // неизвестный atyp
    try testing.expectError(error.BadAddress, interpretReply(&.{ 0x05, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0, 0 }));
    // обрезанный ответ
    try testing.expectError(error.Closed, interpretReply(&.{ 0x05, 0x00, 0x00, 0x01, 0, 0 }));
}
