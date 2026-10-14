//! Короткий инвайт-код: shopot1.<base64url(bundle|имя)>[@host:port]
//! Имя зашито в код — контакт добавляется одной командой без лишних аргументов.
const std = @import("std");

pub const Error = error{
    BadCode,
    BadName,
    BadAddr,
};

pub const max_name = 32;

/// Разобранный инвайт. host_len == 0 — адрес не указан (найдём через LAN).
pub const Invite = struct {
    bundle: [64]u8 = @splat(0),
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,
    host_buf: [64]u8 = undefined,
    host_len: u8 = 0,
    port: u16 = 0,

    pub fn name(self: *const Invite) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn addr(self: *const Invite) ?[]const u8 {
        if (self.host_len == 0) return null;
        return self.host_buf[0..self.host_len];
    }
};

/// Кодирует в буфер. Возвращает срез буфера.
pub fn encode(buf: []u8, bundle: [64]u8, name: []const u8, addr_: ?[]const u8) Error![]const u8 {
    if (name.len == 0 or name.len > max_name) return Error.BadName;
    var raw: [64 + 1 + max_name]u8 = undefined;
    raw[0..64].* = bundle;
    raw[64] = @intCast(name.len);
    @memcpy(raw[65 .. 65 + name.len], name);
    // канонический размер: bundle + 1 + имя (без мусорного хвоста raw).
    // b64 от максимума (97 байт) = 130 знаков — буфер с запасом.
    var b64: [132]u8 = undefined;
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(65 + name.len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(b64[0..enc_len], raw[0 .. 65 + name.len]);
    var n: usize = 0;
    const addr_len: usize = if (addr_) |a| (if (a.len > 0) a.len + 1 else 0) else 0;
    if (buf.len < "shopot1.".len + enc_len + addr_len) return Error.BadCode;
    @memcpy(buf[n .. n + 8], "shopot1.");
    n += 8;
    @memcpy(buf[n .. n + enc_len], b64[0..enc_len]);
    n += enc_len;
    if (addr_) |a| {
        if (a.len > 0) {
            buf[n] = '@';
            n += 1;
            @memcpy(buf[n .. n + a.len], a);
            n += a.len;
        }
    }
    return buf[0..n];
}

test "invite: имя макс. длины + адрес не переполняют буфер" {
    var buf: [256]u8 = undefined;
    var name: [max_name]u8 = @splat('a');
    const code = try encode(&buf, @splat(7), &name, "192.168.100.100:65535");
    // декод обратно: имя и адрес выживают
    const inv = try decode(code);
    try std.testing.expectEqualSlices(u8, &name, inv.name());
    try std.testing.expectEqualStrings("192.168.100.100:65535", inv.addr().?);
}

/// Разбирает код (с префиксом shopot1. или без).
pub fn decode(code: []const u8) Error!Invite {
    var s = code;
    if (std.mem.startsWith(u8, s, "shopot1.")) s = s["shopot1.".len..];
    // хвост @host:port — вне base64url-алфавита
    var host_part: []const u8 = "";
    if (std.mem.lastIndexOfScalar(u8, s, '@')) |at| {
        host_part = s[at + 1 ..];
        s = s[0..at];
    }
    var inv = Invite{};
    var raw: [64 + 1 + max_name]u8 = undefined;
    const dec = std.base64.url_safe_no_pad.Decoder;
    const n = dec.calcSizeForSlice(s) catch return Error.BadCode;
    // канонический размер: bundle + 1 + имя (65..97 байт)
    if (n < 65 + 1 or n > raw.len) return Error.BadCode;
    dec.decode(raw[0..n], s) catch return Error.BadCode;
    inv.bundle = raw[0..64].*;
    const nl = raw[64];
    if (nl == 0 or nl > max_name) return Error.BadName;
    if (65 + @as(usize, nl) != n) return Error.BadCode;
    inv.name_len = nl;
    @memcpy(inv.name_buf[0..nl], raw[65 .. 65 + nl]);
    if (host_part.len > 0) {
        const colon = std.mem.lastIndexOfScalar(u8, host_part, ':') orelse return Error.BadAddr;
        inv.port = std.fmt.parseInt(u16, host_part[colon + 1 ..], 10) catch return Error.BadAddr;
        if (colon == 0 or colon > 64) return Error.BadAddr;
        inv.host_len = @intCast(colon);
        @memcpy(inv.host_buf[0..colon], host_part[0..colon]);
    }
    return inv;
}

test "invite: roundtrip с адресом и без" {
    const testing = std.testing;
    var bundle: [64]u8 = undefined;
    for (&bundle, 0..) |*b, i| b.* = @truncate(i * 7);
    var buf: [256]u8 = undefined;
    const code = try encode(&buf, bundle, "puxxal", "192.168.1.5:7777");
    const inv = try decode(code);
    try testing.expectEqualSlices(u8, &bundle, &inv.bundle);
    try testing.expectEqualStrings("puxxal", inv.name());
    try testing.expectEqualStrings("192.168.1.5:7777", inv.addr().?);
    try testing.expectEqual(@as(u16, 7777), inv.port);
    const code2 = try encode(&buf, bundle, "eryn", null);
    const inv2 = try decode(code2);
    try testing.expectEqualStrings("eryn", inv2.name());
    try testing.expect(inv2.addr() == null);
}
