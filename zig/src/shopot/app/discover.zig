//! LAN-обнаружение контактов без сервера: UDP-мультикаст.
//! Анонс = magic + bundle + TCP-порт. Слышит его только тот, кто уже
//! добавил этот bundle (сверка по хэшу), поэтому шум минимальный.
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const magic = "SHOPOTD1";
pub const group = "239.77.77.77";
pub const udp_port = 57770;
pub const msg_len = magic.len + 64 + 2;

pub const Error = error{
    Network,
    BadPacket,
};

pub const Announce = struct {
    bundle: [64]u8,
    /// TCP-порт, который слушает анонсирующий.
    port: u16,
    /// IPv4 источника (из recvfrom).
    ip: [4]u8,
};

/// Собирает анонс в буфер (msg_len байт).
pub fn buildAnnounce(buf: *[msg_len]u8, bundle: [64]u8, tcp_port: u16) void {
    @memcpy(buf[0..magic.len], magic);
    buf[magic.len .. magic.len + 64].* = bundle;
    std.mem.writeInt(u16, buf[magic.len + 64 ..][0..2], tcp_port, .big);
}

/// Разбирает анонс; чужие/битые пакеты — BadPacket.
pub fn parseAnnounce(buf: []const u8, ip: [4]u8) Error!Announce {
    if (buf.len != msg_len) return Error.BadPacket;
    if (!std.mem.eql(u8, buf[0..magic.len], magic)) return Error.BadPacket;
    return .{
        .bundle = buf[magic.len .. magic.len + 64].*,
        .port = std.mem.readInt(u16, buf[magic.len + 64 ..][0..2], .big),
        .ip = ip,
    };
}

/// Форматирует ip:port в буфер.
pub fn fmtAddr(buf: []u8, ip: [4]u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{ ip[0], ip[1], ip[2], ip[3], port }) catch "?";
}

/// u32 для sockaddr.in.addr: байты в памяти = сетевой порядок (a.b.c.d).
fn readIp4Be(a: u8, b: u8, c: u8, d: u8) u32 {
    var bytes: [4]u8 = .{ a, b, c, d };
    return std.mem.readInt(u32, &bytes, .little);
}

fn ip4(a: u8, b: u8, c: u8, d: u8) u32 {
    return (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | d;
}

/// Сокет мультикаста: приём group:udp_port + отправка. Один fd на всё.
pub const Discovery = struct {
    fd: posix.socket_t,

    pub fn init() Error!Discovery {
        const fd = blk: {
            const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
            if (linux.errno(rc) != .SUCCESS) return Error.Network;
            break :blk @as(posix.socket_t, @intCast(rc));
        };
        // reuse: несколько shopot-ов на одной машине для теста
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)), 4);
        // bind на адрес группы: несколько shopot-процессов на одной машине
        // (и мультикаст-роутеры) доставляют кадр каждому подписчику
        const bind_sa: linux.sockaddr.in = .{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, udp_port),
            .addr = readIp4Be(239, 77, 77, 77),
            .zero = @splat(0),
        };
        if (linux.errno(linux.bind(fd, @ptrCast(&bind_sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
            _ = linux.close(fd);
            return Error.Network;
        }
        // вступить в группу мультикаста
        var mreq: [8]u8 = undefined;
        std.mem.writeInt(u32, mreq[0..4], ip4(239, 77, 77, 77), .big);
        std.mem.writeInt(u32, mreq[4..8], 0, .big); // INADDR_ANY
        if (linux.errno(linux.setsockopt(fd, linux.IPPROTO.IP, linux.IP.ADD_MEMBERSHIP, &mreq, 8)) != .SUCCESS) {
            // без мультикаста (неподдерживающая сеть) — работаем на broadcast-сегменте молча
        }
        // таймаут приёма, чтобы поток мог крутить цикл
        const tv: linux.timeval = .{ .sec = 1, .usec = 0 };
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, &std.mem.toBytes(tv), @sizeOf(linux.timeval));
        return .{ .fd = fd };
    }

    pub fn deinit(self: *Discovery) void {
        _ = linux.close(self.fd);
    }

    /// Разослать свой анонс в группу.
    pub fn announce(self: *Discovery, bundle: [64]u8, tcp_port: u16) void {
        var buf: [msg_len]u8 = undefined;
        buildAnnounce(&buf, bundle, tcp_port);
        var sa: linux.sockaddr.in = .{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, udp_port),
            .addr = readIp4Be(239, 77, 77, 77),
            .zero = @splat(0),
        };
        _ = linux.sendto(self.fd, &buf, buf.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
    }

    /// Ждать анонс до timeout_ms. Возвращает null по таймауту.
    pub fn waitAnnounce(self: *Discovery, timeout_ms: i32) ?Announce {
        var pfd: [1]posix.pollfd = .{.{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 }};
        const n = posix.poll(&pfd, timeout_ms) catch return null;
        if (n == 0) return null;
        var buf: [512]u8 = undefined;
        var sa: linux.sockaddr.in = undefined;
        var sl: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        const rc = linux.recvfrom(self.fd, &buf, buf.len, 0, @ptrCast(&sa), &sl);
        if (linux.errno(rc) != .SUCCESS) return null;
        const ip: [4]u8 = @bitCast(sa.addr);
        return parseAnnounce(buf[0..rc], ip) catch null;
    }
};

test "discover: анонс roundtrip" {
    const testing = std.testing;
    var bundle: [64]u8 = undefined;
    for (&bundle, 0..) |*b, i| b.* = @truncate(i + 3);
    var buf: [msg_len]u8 = undefined;
    buildAnnounce(&buf, bundle, 7777);
    const a = try parseAnnounce(&buf, .{ 192, 168, 1, 9 });
    try testing.expectEqualSlices(u8, &bundle, &a.bundle);
    try testing.expectEqual(@as(u16, 7777), a.port);
    try testing.expectEqual(@as(u8, 192), a.ip[0]);
    try testing.expectError(Error.BadPacket, parseAnnounce(&buf[0 .. msg_len - 1], a.ip));
    var ab: [32]u8 = undefined;
    try testing.expectEqualStrings("192.168.1.9:7777", fmtAddr(&ab, a.ip, a.port));
}
