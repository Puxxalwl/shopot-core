//! Паддинг длины кадров: класс размеров выбирается из buckets, к payload
//! добавляется случайный довесок (до 1/16 класса), остаток забивается нулями.
//! Раскладка кадра: [u16 payload_len LE][payload][random pad][zero pad].

const std = @import("std");

/// Ошибки: TooShort — не хватает буфера или payload вне классов,
/// BadLen — заголовок длины не согласован с данными.
pub const Error = error{ TooShort, BadLen };

/// Классы размеров кадра.
pub const buckets = [_]usize{ 128, 256, 512, 1024, 4096, 16384, 65536 };

/// Максимальный размер payload: кадр с заголовком u16 обязан влезть в класс.
pub const max_payload = buckets[buckets.len - 1] - 2;

/// Возвращает минимальный класс >= `frame` или null, если frame больше последнего.
pub fn bucketFor(frame: usize) ?usize {
    for (buckets) |b| {
        if (b >= frame) return b;
    }
    return null;
}

/// Пишет кадр [u16 payload_len LE][payload][random pad][zero pad] в `out`
/// и возвращает срез длиной ровно в выбранный класс. `extra_rand_bytes`
/// ограничивает случайный довесок сверху: не более 1/16 класса и не более
/// свободного места класса. Случайность берётся из `io`.
pub fn padTo(out: []u8, payload: []const u8, io: std.Io, extra_rand_bytes: usize) Error![]u8 {
    if (payload.len > max_payload) return error.TooShort;
    const frame = 2 + payload.len;
    const bucket = bucketFor(frame) orelse return error.TooShort;
    if (out.len < bucket) return error.TooShort;

    var extra = extra_rand_bytes;
    const max_extra = bucket / 16;
    if (extra > max_extra) extra = max_extra;
    if (extra > bucket - frame) extra = bucket - frame;

    std.mem.writeInt(u16, out[0..2], @intCast(payload.len), .little);
    @memcpy(out[2 .. 2 + payload.len], payload);
    io.random(out[frame .. frame + extra]);
    @memset(out[frame + extra .. bucket], 0);
    return out[0..bucket];
}

/// Извлекает payload из паддированного кадра; согласованный заголовок длины
/// обязателен, иначе BadLen.
pub fn unpad(buf: []const u8) Error![]const u8 {
    if (buf.len < 2) return error.TooShort;
    const len: usize = std.mem.readInt(u16, buf[0..2], .little);
    if (2 + len > buf.len) return error.BadLen;
    return buf[2 .. 2 + len];
}

test "pad: roundtrip и границы классов" {
    const io = std.testing.io;
    var buf: [buckets[buckets.len - 1]]u8 = undefined;

    inline for (buckets) |b| {
        // payload занимает весь класс без заголовка: минимальный запас
        var payload: [b - 2]u8 = undefined;
        @memset(&payload, 0xAB);
        const padded = try padTo(&buf, &payload, io, 0);
        try std.testing.expectEqual(@as(usize, b), padded.len);

        const back = try unpad(padded);
        try std.testing.expectEqualSlices(u8, &payload, back);
    }
}

test "pad: случайные размеры и довесок" {
    const io = std.testing.io;
    var buf: [buckets[buckets.len - 1]]u8 = undefined;

    const sizes = [_]usize{ 0, 1, 2, 100, 126, 127, 200, 400, 900, 4000, 16000, 65000, max_payload };
    for (sizes) |n| {
        var payload: [max_payload]u8 = undefined;
        @memset(payload[0..n], 0x5A);
        const padded = try padTo(&buf, payload[0..n], io, 77);
        const bucket = bucketFor(2 + n).?;
        try std.testing.expectEqual(bucket, padded.len);
        try std.testing.expectEqualSlices(u8, payload[0..n], try unpad(padded));
    }

    // без довеска хвост кадра нулевой
    const padded = try padTo(&buf, "abc", io, 0);
    for (padded[5..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    // довесок ограничен 1/16 класса
    const padded2 = try padTo(&buf, "abc", io, 100000);
    try std.testing.expectEqual(@as(usize, 128), padded2.len);
    try std.testing.expectEqualSlices(u8, "abc", try unpad(padded2));
}

test "pad: TooShort" {
    const io = std.testing.io;
    var big: [buckets[buckets.len - 1]]u8 = undefined;

    // payload больше максимального класса
    var over: [max_payload + 1]u8 = undefined;
    try std.testing.expectError(error.TooShort, padTo(&big, &over, io, 0));

    // буфер вывода меньше класса
    var small: [127]u8 = undefined;
    try std.testing.expectError(error.TooShort, padTo(&small, "abc", io, 0));
}

test "pad: порча заголовка длины -> BadLen" {
    const io = std.testing.io;
    var buf: [256]u8 = undefined;

    const padded = try padTo(&buf, "hello", io, 0);
    try std.testing.expectEqualSlices(u8, "hello", try unpad(padded));

    var broken: [128]u8 = undefined;
    @memcpy(&broken, padded);
    std.mem.writeInt(u16, broken[0..2], 500, .little); // 500 + 2 > 128
    try std.testing.expectError(error.BadLen, unpad(&broken));
}

test "pad: unpad TooShort" {
    try std.testing.expectError(error.TooShort, unpad(&[_]u8{}));
    try std.testing.expectError(error.TooShort, unpad(&[_]u8{1}));
}
