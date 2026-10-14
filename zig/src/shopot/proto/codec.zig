//! codec — безаллокационные little-endian Reader/Writer над буфером.
//!
//! Примитив кадрирования протокола v3: всё little-endian через
//! `std.mem.readInt/writeInt`, длины — фиксированные u16, никакого varint.
//! Аллокаций нет: вызывающий передаёт свой буфер, Reader возвращает срезы
//! в него же.

const std = @import("std");

/// Писатель: заполняет предоставленный буфер little-endian байтами.
pub const Writer = struct {
    /// Целевой буфер.
    buf: []u8,
    /// Текущая позиция записи.
    pos: usize = 0,

    /// Ошибка записи: в буфере нет места (или payload не влезает в u16-длину).
    pub const Error = error{NoSpace};

    /// Новый писатель над `buf`.
    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    /// Число записанных байтов.
    pub fn written(self: *const Writer) usize {
        return self.pos;
    }

    /// Оставшаяся ёмкость буфера.
    pub fn remaining(self: *const Writer) usize {
        return self.buf.len - self.pos;
    }

    /// Записать один байт.
    pub fn put(self: *Writer, byte: u8) Error!void {
        if (self.remaining() < 1) return error.NoSpace;
        self.buf[self.pos] = byte;
        self.pos += 1;
    }

    /// Записать беззнаковое целое (u16/u32/u64/...) little-endian.
    pub fn putInt(self: *Writer, comptime T: type, value: T) Error!void {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        if (self.remaining() < n) return error.NoSpace;
        std.mem.writeInt(T, self.buf[self.pos..][0..n], value, .little);
        self.pos += n;
    }

    /// Записать `bytes` с префиксом длины u16 (little-endian).
    /// NoSpace, если длина payload превышает maxInt(u16).
    pub fn putBytes(self: *Writer, bytes: []const u8) Error!void {
        if (bytes.len > std.math.maxInt(u16)) return error.NoSpace;
        try self.putInt(u16, @intCast(bytes.len));
        try self.writeAll(bytes);
    }

    /// Записать ровно `fixed.len` байтов без префикса длины.
    pub fn putFixed(self: *Writer, fixed: []const u8) Error!void {
        try self.writeAll(fixed);
    }

    fn writeAll(self: *Writer, bytes: []const u8) Error!void {
        if (self.remaining() < bytes.len) return error.NoSpace;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }
};

/// Читатель: разбирает little-endian кадр из предоставленного буфера.
pub const Reader = struct {
    /// Исходный буфер кадра.
    buf: []const u8,
    /// Текущая позиция чтения.
    pos: usize = 0,

    /// Ошибка чтения: данных в буфере меньше, чем запрошено.
    pub const Error = error{Truncated};

    /// Новый читатель над `buf`.
    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    /// Сколько байтов ещё не прочитано.
    pub fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    /// true, если весь буфер прочитан до конца.
    pub fn done(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }

    /// Прочитать один байт.
    pub fn getU8(self: *Reader) Error!u8 {
        if (self.remaining() < 1) return error.Truncated;
        const byte = self.buf[self.pos];
        self.pos += 1;
        return byte;
    }

    /// Прочитать беззнаковое целое (u16/u32/u64/...) little-endian.
    pub fn getInt(self: *Reader, comptime T: type) Error!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        if (self.remaining() < n) return error.Truncated;
        const value = std.mem.readInt(T, self.buf[self.pos..][0..n], .little);
        self.pos += n;
        return value;
    }

    /// Прочитать байты с префиксом длины u16; вернуть срез исходного буфера
    /// (без копии). Данные, заявленные длиной, обязаны присутствовать.
    pub fn getBytes(self: *Reader) Error![]const u8 {
        const len = try self.getInt(u16);
        return self.getFixed(len);
    }

    /// Прочитать ровно `n` байтов; вернуть срез исходного буфера (без копии).
    pub fn getFixed(self: *Reader, n: usize) Error![]const u8 {
        if (self.remaining() < n) return error.Truncated;
        const slice = self.buf[self.pos..][0..n];
        self.pos += n;
        return slice;
    }
};

const testing = std.testing;

test "Writer/Reader: roundtrip u8/u16/u32/u64" {
    var buf: [15]u8 = undefined;
    var w = Writer.init(&buf);
    try w.put(0xAB);
    try w.putInt(u16, 0x1234);
    try w.putInt(u32, 0xDEAD_BEEF);
    try w.putInt(u64, 0x0123_4567_89AB_CDEF);

    try testing.expectEqual(@as(usize, 15), w.written());
    try testing.expectEqual(@as(usize, 0), w.remaining());

    var r = Reader.init(w.buf[0..w.written()]);
    try testing.expectEqual(@as(u8, 0xAB), try r.getU8());
    try testing.expectEqual(@as(u16, 0x1234), try r.getInt(u16));
    try testing.expectEqual(@as(u32, 0xDEAD_BEEF), try r.getInt(u32));
    try testing.expectEqual(@as(u64, 0x0123_4567_89AB_CDEF), try r.getInt(u64));
    try testing.expect(r.done());
}

test "Writer: little-endian раскладка байтов" {
    var buf: [6]u8 = undefined;
    var w = Writer.init(&buf);
    try w.putInt(u32, 0xAABB_CCDD);
    try w.putInt(u16, 0x1234);
    try testing.expectEqualSlices(u8, &.{ 0xDD, 0xCC, 0xBB, 0xAA, 0x34, 0x12 }, w.buf[0..6]);
}

test "Writer/Reader: putBytes/getBytes roundtrip" {
    var buf: [32]u8 = undefined;
    var w = Writer.init(&buf);
    try w.putBytes("шёпот"); // 10 байтов UTF-8
    try w.putBytes("");

    try testing.expectEqual(@as(usize, 2 + 10 + 2), w.written());

    var r = Reader.init(w.buf[0..w.written()]);
    try testing.expectEqualStrings("шёпот", try r.getBytes());
    try testing.expectEqual(@as(usize, 0), (try r.getBytes()).len);
    try testing.expect(r.done());
}

test "Reader: getFixed возвращает срез исходного буфера (без копии)" {
    var buf: [8]u8 = undefined;
    @memcpy(buf[0..5], "fixed");
    var r = Reader.init(buf[0..5]);
    const slice = try r.getFixed(5);
    try testing.expectEqualStrings("fixed", slice);
    try testing.expect(slice.ptr == buf[0..5].ptr);
    try testing.expect(r.done());
}

test "Writer: переполнение буфера -> NoSpace, позиция не съезжает" {
    var buf: [2]u8 = undefined;
    var w = Writer.init(&buf);
    try w.putInt(u16, 0xFFFF); // буфер исчерпан

    try testing.expectError(error.NoSpace, w.put(0));
    try testing.expectError(error.NoSpace, w.putInt(u16, 1));
    try testing.expectError(error.NoSpace, w.putFixed("ab"));
    try testing.expectError(error.NoSpace, w.putBytes("ab"));
    try testing.expectEqual(@as(usize, 2), w.written());
}

test "Writer: putBytes с payload больше u16 -> NoSpace" {
    var buf: [16]u8 = undefined;
    var w = Writer.init(&buf);
    const big: [std.math.maxInt(u16) + 1]u8 = @splat(0);
    try testing.expectError(error.NoSpace, w.putBytes(&big));
}

test "Reader: усечение -> Truncated" {
    var buf: [8]u8 = undefined;
    var w = Writer.init(&buf);
    try w.putInt(u32, 7);

    var r = Reader.init(w.buf[0..w.written()]);
    try testing.expectError(error.Truncated, r.getInt(u64));
    try testing.expectEqual(@as(u32, 7), try r.getInt(u32));
    try testing.expectError(error.Truncated, r.getU8());
    try testing.expectError(error.Truncated, r.getFixed(1));
    try testing.expectError(error.Truncated, r.getBytes());

    var short = Reader.init(w.buf[0..1]);
    try testing.expectError(error.Truncated, short.getInt(u32));
    try testing.expectError(error.Truncated, short.getBytes()); // префикс длины не влезает
}

test "Reader: пустой буфер -> Truncated" {
    var r = Reader.init(&[_]u8{});
    try testing.expect(r.done());
    try testing.expectEqual(@as(usize, 0), r.remaining());
    try testing.expectError(error.Truncated, r.getU8());
}
