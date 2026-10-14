//! Одноразовые ключи аудиовызова: keyFor(seq) = HKDF-Expand(call_secret,
//! "shopot-call-v3" || u32 LE seq). Уникальность seq (одноразовость ключа) —
//! обязанность вызывающего.

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

const domain = "shopot-call-v3";

/// Выводит 32-байтовый ключ аудиокадра для порядкового номера `seq`.
pub fn keyFor(call_secret: [32]u8, seq: u32) [32]u8 {
    var info: [domain.len + 4]u8 = undefined;
    @memcpy(info[0..domain.len], domain);
    std.mem.writeInt(u32, info[domain.len..][0..4], seq, .little);

    var key: [32]u8 = undefined;
    HkdfSha256.expand(&key, &info, call_secret);
    return key;
}

test "call_keys: разные seq -> разные ключи" {
    const secret: [32]u8 = @splat(9);
    const k0 = keyFor(secret, 0);
    const k1 = keyFor(secret, 1);
    const kmax = keyFor(secret, 0xffffffff);
    try std.testing.expect(!std.mem.eql(u8, &k0, &k1));
    try std.testing.expect(!std.mem.eql(u8, &k0, &kmax));
    try std.testing.expect(!std.mem.eql(u8, &k1, &kmax));
}

test "call_keys: детерминизм" {
    const secret: [32]u8 = @splat(9);
    const a = keyFor(secret, 12345);
    const b = keyFor(secret, 12345);
    try std.testing.expectEqualSlices(u8, &a, &b);

    const secret2: [32]u8 = @splat(10);
    const c = keyFor(secret2, 12345);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}
