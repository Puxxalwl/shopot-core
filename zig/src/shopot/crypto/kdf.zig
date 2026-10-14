//! HKDF-SHA256 (RFC 5869) — тонкие обёртки над std.crypto.kdf.
//! Собственных примитивов нет: только композиция std.

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// Длина псевдослучайного ключа (PRK), в байтах (SHA-256 -> 32).
pub const prk_length = HkdfSha256.prk_length;

/// Фаза extract: prk = HMAC-SHA256(salt, ikm).
pub fn extract(salt: []const u8, ikm: []const u8) [prk_length]u8 {
    return HkdfSha256.extract(salt, ikm);
}

/// Фаза expand: заполняет `okm` выходным материалом HKDF-Expand(prk, info).
pub fn expand(prk: [prk_length]u8, info: []const u8, okm: []u8) void {
    HkdfSha256.expand(okm, info, prk);
}

test "kdf: RFC 5869 test case 1 (SHA-256)" {
    var ikm: [22]u8 = @splat(0x0b);
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    const prk = extract(&salt, &ikm);
    const prk_expected = [_]u8{
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
        0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
        0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
    };
    try std.testing.expectEqual(prk_expected, prk);

    var okm: [42]u8 = undefined;
    expand(prk, &info, &okm);
    const okm_expected = [_]u8{
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43,
        0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90,
        0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    };
    try std.testing.expectEqualSlices(u8, &okm_expected, &okm);
}

test "kdf: префиксное свойство expand" {
    var ikm: [32]u8 = undefined;
    var salt: [32]u8 = undefined;
    for (&ikm, 0..) |*b, i| b.* = @truncate(i);
    for (&salt, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);

    const prk = extract(&salt, &ikm);
    var short: [16]u8 = undefined;
    var long: [64]u8 = undefined;
    expand(prk, "shopot-ctx", &short);
    expand(prk, "shopot-ctx", &long);
    try std.testing.expectEqualSlices(u8, &short, long[0..16]);

    var other: [16]u8 = undefined;
    expand(prk, "shopot-ctx2", &other);
    try std.testing.expect(!std.mem.eql(u8, &short, &other));
}
