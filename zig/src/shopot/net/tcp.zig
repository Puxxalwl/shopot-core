//! TCP-транспорт: сырые POSIX-сокеты, адаптер к интерфейсу Conn. std-only.
//! Намеренно БЕЗ std.Io: блокирующие fd в отдельных потоках — самый
//! предсказуемый режим для CLI (Threaded io конкурирует между потоками).
const std = @import("std");
const posix = std.posix;
const interfaces = @import("../core/interfaces.zig");

pub const TcpConn = struct {
    fd: posix.socket_t,

    pub fn deinit(self: *TcpConn) void {
        _ = std.os.linux.close(self.fd);
    }

    fn readAllImpl(ptr: *anyopaque, buf: []u8) interfaces.ConnError!void {
        const self: *TcpConn = @ptrCast(@alignCast(ptr));
        var got: usize = 0;
        while (got < buf.len) {
            const n = posix.read(self.fd, buf[got..]) catch return error.Closed;
            if (n == 0) return error.Closed;
            got += n;
        }
    }

    fn writeAllImpl(ptr: *anyopaque, bytes: []const u8) interfaces.ConnError!void {
        const self: *TcpConn = @ptrCast(@alignCast(ptr));
        var sent: usize = 0;
        while (sent < bytes.len) {
            const rc = std.os.linux.write(self.fd, bytes[sent..].ptr, bytes.len - sent);
            if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
            if (rc == 0) return error.Network;
            sent += rc;
        }
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *TcpConn = @ptrCast(@alignCast(ptr));
        _ = std.os.linux.close(self.fd);
    }

    const vtable = interfaces.Conn.VTable{
        .readAll = readAllImpl,
        .writeAll = writeAllImpl,
        .close = closeImpl,
    };

    /// Vtable-адаптер для ядра.
    pub fn conn(self: *TcpConn) interfaces.Conn {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

pub const DialError = error{
    BadAddress,
    Network,
    OutOfMemory,
};

const linux = std.os.linux;

/// sockaddr.in из IPv4-литерала + порт. Поддержка IPv6-литералов — позже.
fn parseV4(host: []const u8, port: u16) ?linux.sockaddr.in {
    const ip4 = std.Io.net.Ip4Address.parse(host, port) catch return null;
    return .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        // байты адреса лежат в памяти как есть (сетевой порядок байт)
        .addr = std.mem.readInt(u32, &ip4.bytes, .little),
        .zero = @splat(0),
    };
}

/// Dial "host:port" (IPv4-литерал; домены не поддержаны в этой версии).
pub fn dial(alloc: std.mem.Allocator, addr: []const u8) DialError!*TcpConn {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.BadAddress;
    const host = addr[0..colon];
    const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.BadAddress;
    var sa = parseV4(host, port) orelse return error.BadAddress;
    const fd = blk: {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (linux.errno(rc) != .SUCCESS) return error.Network;
        break :blk @as(posix.socket_t, @intCast(rc));
    };
    const rc = linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
    if (linux.errno(rc) != .SUCCESS) {
        _ = linux.close(fd);
        return error.Network;
    }
    const tc = alloc.create(TcpConn) catch {
        _ = linux.close(fd);
        return error.OutOfMemory;
    };
    tc.* = .{ .fd = fd };
    setKeepalive(fd);
    return tc;
}

/// Ядро само детектит мёртвый peer (30с тишины TCP-уровня, без прикладных
/// запросов) — presence-пинги остаются только для статуса «онлайн».
pub fn setKeepalive(fd: posix.socket_t) void {
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(@as(c_int, 1))) catch return;
    posix.setsockopt(fd, linux.IPPROTO.TCP, 4, &std.mem.toBytes(@as(c_int, 30))) catch return; // KEEPIDLE
    posix.setsockopt(fd, linux.IPPROTO.TCP, 5, &std.mem.toBytes(@as(c_int, 10))) catch return; // KEEPINTVL
    posix.setsockopt(fd, linux.IPPROTO.TCP, 9, &std.mem.toBytes(@as(c_int, 3))) catch return; // KEEPCNT
}

/// Готовый к accept() слушатель.
pub const Listener = struct {
    fd: posix.socket_t,

    /// Блокирующий accept; возвращает адаптированный TcpConn.
    pub fn accept(self: *Listener, alloc: std.mem.Allocator) !*TcpConn {
        var sa: linux.sockaddr.storage = undefined;
        var sl: linux.socklen_t = @sizeOf(linux.sockaddr.storage);
        const rc = linux.accept4(self.fd, @ptrCast(&sa), &sl, 0);
        if (linux.errno(rc) != .SUCCESS) return error.Network;
        const cfd: posix.socket_t = @intCast(rc);
        const tc = alloc.create(TcpConn) catch {
            _ = linux.close(cfd);
            return error.OutOfMemory;
        };
        tc.* = .{ .fd = cfd };
        setKeepalive(cfd);
        return tc;
    }

    pub fn deinit(self: *Listener) void {
        posix.close(self.fd);
    }
};

pub const ListenError = error{
    BadAddress,
    Network,
};

/// Слушать "host:port". SO_REUSEADDR включён — перезапуск без TIME_WAIT-паузы.
pub fn listen(addr: []const u8) ListenError!Listener {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.BadAddress;
    const host = addr[0..colon];
    const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.BadAddress;
    var sa = parseV4(host, port) orelse return error.BadAddress;
    const fd = blk: {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (linux.errno(rc) != .SUCCESS) return error.Network;
        break :blk @as(posix.socket_t, @intCast(rc));
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};
    {
        const rc = linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
        const e = linux.errno(rc);
        if (e != .SUCCESS) {
            std.debug.print("[listen] bind errno={s}\n", .{@tagName(e)});
            _ = linux.close(fd);
            return error.Network;
        }
    }
    {
        const rc = linux.listen(fd, 16);
        const e = linux.errno(rc);
        if (e != .SUCCESS) {
            std.debug.print("[listen] listen errno={s}\n", .{@tagName(e)});
            _ = linux.close(fd);
            return error.Network;
        }
    }
    return .{ .fd = fd };
}

test "dial bad address fails clean" {
    try std.testing.expectError(error.BadAddress, dial(std.testing.allocator, "no-colon"));
}
