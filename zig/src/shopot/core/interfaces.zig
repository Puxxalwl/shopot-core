//! Interface (vtable) contracts. Every layer depends only on these shapes —
//! concrete implementations are injected, which keeps modules independently
//! testable and the dependency graph one-directional.
const std = @import("std");

pub const ConnError = error{
    Closed,
    WouldBlock,
    Network,
    Tampered,
};

/// One established, obfuscated, bidirectional byte stream.
pub const Conn = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Read exactly buf.len bytes or ConnError.Closed. May block.
        readAll: *const fn (ptr: *anyopaque, buf: []u8) ConnError!void,
        /// Write the whole buffer or fail. May block.
        writeAll: *const fn (ptr: *anyopaque, buf: []const u8) ConnError!void,
        close: *const fn (ptr: *anyopaque) void,
    };

    pub fn readAll(self: Conn, buf: []u8) ConnError!void {
        return self.vtable.readAll(self.ptr, buf);
    }
    pub fn writeAll(self: Conn, buf: []const u8) ConnError!void {
        return self.vtable.writeAll(self.ptr, buf);
    }
    pub fn close(self: Conn) void {
        self.vtable.close(self.ptr);
    }
};

/// Dials outbound connections / accepts inbound ones.
pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        dial: *const fn (ptr: *anyopaque, addr: []const u8, alloc: std.mem.Allocator) anyerror!Conn,
    };

    pub fn dial(self: Transport, addr: []const u8, alloc: std.mem.Allocator) anyerror!Conn {
        return self.vtable.dial(self.ptr, addr, alloc);
    }
};

/// Monotonic clock abstraction (injected so tests run without real time).
pub const Clock = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        nowMs: *const fn (ptr: *anyopaque) i64,
    };

    pub fn nowMs(self: Clock) i64 {
        return self.vtable.nowMs(self.ptr);
    }
};

/// Wall clock backed by the injected std.Io (CLOCK_REALTIME semantics);
/// the vtable shape keeps it interchangeable with test clocks.
pub const WallClock = struct {
    io: std.Io,

    fn nowMsImpl(ptr: *anyopaque) i64 {
        const self: *WallClock = @ptrCast(@alignCast(ptr));
        const ts = std.Io.Clock.now(.real, self.io);
        return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
    }
    const vtable = Clock.VTable{ .nowMs = nowMsImpl };

    pub fn clock(self: *WallClock) Clock {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

test "wall clock sane" {
    var wc = WallClock{ .io = std.testing.io };
    const c = wc.clock();
    try std.testing.expect(c.nowMs() > 1_600_000_000_000);
}
