//! ChaCha20-Poly1305 AEAD (std.crypto.aead.chacha_poly.ChaCha20Poly1305).
//! Формат box: ciphertext || tag. Nonce собирается из u64-счётчика:
//! [0,0,0,0] || counter LE.

const std = @import("std");

const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

/// Длина тега Poly1305, в байтах.
pub const tag_length = Aead.tag_length;

/// Длина ключа, в байтах.
pub const key_length = Aead.key_length;

/// Длина nonce, в байтах.
pub const nonce_length = Aead.nonce_length;

/// Ошибки расшифровки: TooShort — мало данных или мал буфер вывода,
/// Tampered — тег не сошёлся (битые данные, чужой ключ/nonce/ad).
pub const Error = error{ Tampered, TooShort };

/// Собирает 12-байтовый nonce из 64-битного счётчика: [0,0,0,0] || counter LE.
pub fn nonceFor(counter: u64) [nonce_length]u8 {
    var nonce: [nonce_length]u8 = @splat(0);
    std.mem.writeInt(u64, nonce[4..12], counter, .little);
    return nonce;
}

/// Шифрует `plain` в `out_box` (длина >= plain.len + tag_length): ciphertext || tag.
pub fn seal(out_box: []u8, plain: []const u8, key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8) void {
    std.debug.assert(out_box.len >= plain.len + tag_length);
    const c = out_box[0..plain.len];
    const tag = out_box[plain.len..][0..tag_length];
    Aead.encrypt(c, tag, plain, ad, nonce, key);
}

/// Расшифровывает `box` (ciphertext || tag) в `plain_out` (длина >= box.len - tag_length).
pub fn open(plain_out: []u8, box: []const u8, key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8) Error!void {
    if (box.len < tag_length) return error.TooShort;
    const c_len = box.len - tag_length;
    if (plain_out.len < c_len) return error.TooShort;
    const tag: [tag_length]u8 = box[c_len..][0..tag_length].*;
    Aead.decrypt(plain_out[0..c_len], box[0..c_len], tag, ad, nonce, key) catch return error.Tampered;
}

test "aead: roundtrip" {
    const key: [32]u8 = @splat(7);
    const nonce = nonceFor(42);
    const plain = "hello shopot";

    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, plain, key, nonce, "ad");

    var out: [plain.len]u8 = undefined;
    try open(&out, &buf, key, nonce, "ad");
    try std.testing.expectEqualSlices(u8, plain, &out);
}

test "aead: битый байт -> Tampered" {
    const key: [32]u8 = @splat(7);
    const nonce = nonceFor(1);
    const plain = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, &plain, key, nonce, "ad");

    var out: [plain.len]u8 = undefined;

    // порча шифротекста
    buf[3] ^= 0x01;
    try std.testing.expectError(error.Tampered, open(&out, &buf, key, nonce, "ad"));

    // порча тега
    buf[3] ^= 0x01;
    buf[buf.len - 1] ^= 0x80;
    try std.testing.expectError(error.Tampered, open(&out, &buf, key, nonce, "ad"));
}

test "aead: другой AD -> Tampered" {
    const key: [32]u8 = @splat(7);
    const nonce = nonceFor(2);
    const plain = "payload";

    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, plain, key, nonce, "header-a");

    var out: [plain.len]u8 = undefined;
    try std.testing.expectError(error.Tampered, open(&out, &buf, key, nonce, "header-b"));
}

test "aead: чужой ключ -> Tampered" {
    const key: [32]u8 = @splat(7);
    const other_key: [32]u8 = @splat(8);
    const nonce = nonceFor(3);
    const plain = "payload";

    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, plain, key, nonce, "");

    var out: [plain.len]u8 = undefined;
    try std.testing.expectError(error.Tampered, open(&out, &buf, other_key, nonce, ""));
}

test "aead: nonceFor раскладка счётчика" {
    const n = nonceFor(1);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, n[0..4]);
    try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, n[4..12], .little));
    const big = nonceFor(0x0102030405060708);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), std.mem.readInt(u64, big[4..12], .little));
}

test "aead: TooShort" {
    const key: [32]u8 = @splat(7);
    const nonce = nonceFor(4);

    // box короче тега
    var out: [32]u8 = undefined;
    try std.testing.expectError(error.TooShort, open(&out, &[_]u8{ 9, 9, 9, 9, 9, 9, 9, 9 }, key, nonce, ""));

    // нормальный box, но буфер вывода мал
    const plain = [_]u8{ 1, 2, 3 };
    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, &plain, key, nonce, "");
    var small: [2]u8 = undefined;
    try std.testing.expectError(error.TooShort, open(&small, &buf, key, nonce, ""));
}
