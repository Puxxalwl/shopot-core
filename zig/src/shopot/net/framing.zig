//! Формат кадра поверх шифрованного потока: [len u16 LE][payload].
//! Только формат: шифрование и выравнивание длин — в obfuscate.zig, не здесь.
const std = @import("std");

/// Максимальный размер полезной нагрузки кадра.
pub const max_frame: u16 = 65535;

/// Размер заголовка кадра: длина payload как u16 little-endian.
pub const header_len: usize = @sizeOf(u16);

pub const Error = error{
    /// Payload не помещается в кадр (больше max_frame).
    TooLong,
};

/// Полная длина кадра на проводе (заголовок + payload).
pub fn encodedLen(payload_len: usize) Error!usize {
    if (payload_len > max_frame) return error.TooLong;
    return header_len + payload_len;
}

/// Кодирует заголовок кадра: [u16 LE payload_len].
pub fn encodeHeader(dest: *[header_len]u8, payload_len: u16) void {
    std.mem.writeInt(u16, dest, payload_len, .little);
}

/// Разбирает заголовок, записанный encodeHeader, в длину payload.
pub fn decodeHeader(header: *const [header_len]u8) u16 {
    return std.mem.readInt(u16, header, .little);
}

/// Пишет кадр [len u16 LE][payload] в writer.
pub fn writeFrame(writer: *std.Io.Writer, payload: []const u8) (std.Io.Writer.Error || Error)!void {
    if (payload.len > max_frame) return error.TooLong;
    var hdr: [header_len]u8 = undefined;
    encodeHeader(&hdr, @intCast(payload.len));
    try writer.writeAll(&hdr);
    try writer.writeAll(payload);
}

/// Читает из reader заголовок кадра и возвращает длину payload (0..max_frame).
pub fn readFrameLen(reader: *std.Io.Reader) std.Io.Reader.Error!u16 {
    var hdr: [header_len]u8 = undefined;
    try reader.readSliceAll(&hdr);
    return decodeHeader(&hdr);
}

test "framing: encode/decode roundtrip через Writer/Reader" {
    const testing = std.testing;
    var buf: [max_frame + header_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const payload = "shopot-frame-payload";
    try writeFrame(&w, payload);
    const wire = w.buffered();
    try testing.expectEqual(try encodedLen(payload.len), wire.len);

    var r: std.Io.Reader = .fixed(wire);
    try testing.expectEqual(@as(u16, payload.len), try readFrameLen(&r));
    var got: [payload.len]u8 = undefined;
    try r.readSliceAll(&got);
    try testing.expectEqualStrings(payload, &got);
}

test "framing: пустой payload" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeFrame(&w, "");
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, w.buffered());
    var r: std.Io.Reader = .fixed(w.buffered());
    try testing.expectEqual(@as(u16, 0), try readFrameLen(&r));
}

test "framing: максимальная длина и TooLong" {
    const testing = std.testing;
    var big: [max_frame]u8 = undefined;
    @memset(&big, 0xAB);
    var buf: [max_frame + header_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeFrame(&w, &big);
    try testing.expectEqual(header_len + @as(usize, max_frame), w.buffered().len);
    // заголовок ровно 65535 little-endian
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF }, w.buffered()[0..2]);

    var too_long: [@as(usize, max_frame) + 1]u8 = undefined;
    try testing.expectError(error.TooLong, writeFrame(&w, &too_long));
    try testing.expectError(error.TooLong, encodedLen(@as(usize, max_frame) + 1));
}

test "framing: заголовок явно little-endian" {
    const testing = std.testing;
    var hdr: [header_len]u8 = undefined;
    encodeHeader(&hdr, 0x0102);
    try testing.expectEqual(@as(u16, 0x0102), decodeHeader(&hdr));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x01 }, &hdr);
}
