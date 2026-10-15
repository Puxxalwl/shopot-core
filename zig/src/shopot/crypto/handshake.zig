//! XX-подобный рукопожатие: транскрипт BLAKE2s-256, DH X25519 (ee/es/se),
//! шифрование статиков и подписей ChaCha20-Poly1305, подписи Ed25519 над
//! хэшем транскрипта. Ноль аллокаций: все сообщения и состояние — на буферах
//! и в стеке вызывающего. Эфемеральные ключи задаёт вызывающий сидами.
//!
//! Раскладка сообщений:
//!   m1 = e1_pub                                            (32)
//!   m2 = e2_pub || box(resp_enc_pk || sig_r)               (144)
//!   m3 = box(init_enc_pk || sig_i)                         (112)
//!
//! Последовательность MixKey (одинакова у сторон):
//!   h0 = ck0 = BLAKE2s256("shopot-hs-v3")
//!   h1 = H(h0||e1);  h2 = H(h1||e2);  ee = X25519(e2,e1) -> k1, ck
//!   sig_r = Sign_r(h2);  box1 = Seal(k1, n=0, ad=h2);  h3 = H(h2||box1)
//!   es = X25519(s_r,e1) -> k2, ck
//!   sig_i = Sign_i(h3);  box2 = Seal(k2, n=1, ad=h3);  h4 = H(h3||box2)
//!   se = X25519(s_i,e2) -> ck
//!   (send_key, recv_key) = HKDF-Expand(ck, "shopot-hs-finish")

const std = @import("std");

const identity = @import("identity.zig");
const aead = @import("aead.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;

const domain = "shopot-hs-v3";
const mix_info = "shopot-hs-mix";
const finish_info = "shopot-hs-finish";

const payload_len = 32 + 64; // статический ключ || подпись Ed25519

/// Длина m1: e1_pub (32) || init enc_pk (32). enc_pk идёт открытым текстом
/// только для маршрутизации у responder-а; личность доказывается подписью
/// в m3 (транскрипт покрывает e1_pub, enc_pk проверяется через sig в m3).
pub const m1_len = 64;

/// Длина m2: e2_pub (32) || box (payload_len + tag).
pub const m2_len = 32 + payload_len + aead.tag_length;

/// Длина m3: box (payload_len + tag).
pub const m3_len = payload_len + aead.tag_length;

/// Длина подписи Ed25519.
pub const sig_len = 64;

/// Ошибки рукопожатия.
pub const Error = error{
    /// Неверная длина сообщения.
    BadLength,
    /// AEAD не открылся (чужие эфемерки, битые байты, вырожденный DH).
    Tampered,
    /// Подпись транскрипта не сошлась.
    BadSignature,
    /// Статический ключ X25519 в боксе не равен ожидаемому из bundle
    /// контакта (привязка личности к статике; практика libp2p-noise:
    /// приложение обязано проверить remote static после XX).
    KeyMismatch,
};

/// Сессионные ключи; send/recv зеркальны у двух сторон.
pub const SessionKeys = struct {
    /// Ключ шифрования исходящих сообщений.
    send_key: [32]u8,
    /// Ключ расшифровки входящих сообщений.
    recv_key: [32]u8,
    /// Финальный хэш транскрипта (совпадает у сторон).
    transcript: [32]u8,
};

/// BLAKE2s-256 над конкатенацией частей.
fn hashParts(parts: []const []const u8) [32]u8 {
    var h = Blake2s256.init(.{});
    for (parts) |p| h.update(p);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// MixKey: (ck, key) = HKDF(ck, ikm); ck обновляется на месте, возвращается
/// новый ключ шифрования.
fn mixKey(ck: *[32]u8, ikm: []const u8) [32]u8 {
    var prk = HkdfSha256.extract(ck, ikm);
    var okm: [64]u8 = undefined;
    HkdfSha256.expand(&okm, mix_info, prk);
    std.crypto.secureZero(u8, &prk);

    ck.* = okm[0..32].*;
    const key = okm[32..64].*;
    @memset(okm[32..64], 0);
    return key;
}

/// Подписывает `transcript` парой Ed25519 личности (пара кэшируется в
/// Identity с fromSeed — повторного скалярного вывода нет). Ошибки
/// подписи схлопнуты в error.Tampered: для валидной личности недостижимы.
fn signTranscript(id: *const identity.Identity, transcript: [32]u8, sig_out: *[sig_len]u8) error{Tampered}!void {
    id.sign(&transcript, sig_out) catch return error.Tampered;
}

/// Инициатор (первый в рукопожатии).
pub const Initiator = struct {
    h: [32]u8,
    ck: [32]u8,
    eph_secret: [32]u8,
    my_id: *const identity.Identity,

    /// Начинает рукопожатие: пишет m1 (эфемерный X25519 из `eph_seed`).
    pub fn start(out_m1: *[m1_len]u8, my_id: *const identity.Identity, eph_seed: [32]u8) Initiator {
        var h0: [32]u8 = undefined;
        Blake2s256.hash(domain, &h0, .{});

        const eph = X25519.KeyPair.generateDeterministic(eph_seed);
        out_m1[0..32].* = eph.public_key;
        out_m1[32..64].* = my_id.enc_public;

        return .{
            .h = hashParts(&[_][]const u8{ &h0, out_m1 }),
            .ck = h0,
            .eph_secret = eph.secret_key,
            .my_id = my_id,
        };
    }

    /// Обрабатывает m2 (проверяет sig по `peer_sign_public`, сверяет
    /// статический ключ с `peer_enc_public`, если тот известен), пишет m3,
    /// возвращает сессионные ключи. Сверка статики закрывает разрыв
    /// «sig покрывает транскрипт до бокса»: без неё сессионный ключ мог
    /// быть выведен с чужой статикой, не равной bundle контакта.
    pub fn recv2(self: *Initiator, out_m3: *[m3_len]u8, m2: []const u8, peer_sign_public: [32]u8, peer_enc_public: ?[32]u8) Error!SessionKeys {
        if (m2.len != m2_len) return error.BadLength;

        const e2_public: [32]u8 = m2[0..32].*;
        const box1: []const u8 = m2[32..];

        // h2 = H(h1||e2)
        self.h = hashParts(&[_][]const u8{ &self.h, &e2_public });

        // ee = X25519(e_i, e_r) -> k1
        const ee = X25519.scalarmult(self.eph_secret, e2_public) catch return error.Tampered;
        const k1 = mixKey(&self.ck, &ee);

        // открыть box1: resp_enc_pk || sig_r (ad = h2)
        var payload: [payload_len]u8 = undefined;
        aead.open(&payload, box1, k1, aead.nonceFor(0), &self.h) catch return error.Tampered;
        const resp_enc_public: [32]u8 = payload[0..32].*;
        const sig_r: [sig_len]u8 = payload[32..payload_len].*;
        @memset(&payload, 0);

        // статический ключ обязан совпадать с известным bundle контакта
        if (peer_enc_public) |expected| {
            if (!std.mem.eql(u8, &resp_enc_public, &expected)) return error.KeyMismatch;
        }

        // подпись ответчика над транскриптом h2
        try identity.Identity.verify(peer_sign_public, &self.h, sig_r);

        // транскрипт после m2
        self.h = hashParts(&[_][]const u8{ &self.h, box1 });
        const h3 = self.h;

        // es = X25519(e_i, s_r) -> k2
        const es = X25519.scalarmult(self.eph_secret, resp_enc_public) catch return error.Tampered;
        const k2 = mixKey(&self.ck, &es);

        // m3: box(init_enc_pk || sig_i), ad = h3
        var payload3: [payload_len]u8 = undefined;
        payload3[0..32].* = self.my_id.enc_public;
        try signTranscript(self.my_id, h3, payload3[32..payload_len]);
        aead.seal(out_m3, &payload3, k2, aead.nonceFor(1), &h3);
        @memset(&payload3, 0);

        // транскрипт после m3
        self.h = hashParts(&[_][]const u8{ &h3, out_m3 });

        // se = X25519(s_i, e_r) -> ck
        const se = X25519.scalarmult(self.my_id.enc_secret, e2_public) catch return error.Tampered;
        _ = mixKey(&self.ck, &se);

        return finishKeys(self.ck, self.h, .initiator);
    }
};

/// Ответчик.
pub const Responder = struct {
    h: [32]u8,
    ck: [32]u8,
    k2: [32]u8,
    e2_secret: [32]u8,
    my_id: *const identity.Identity,

    /// Обрабатывает m1, пишет m2 (эфемерный X25519 из `eph_seed`;
    /// sig подписывается сидом Ed25519 из `my_id`).
    pub fn recv1(out_m2: *[m2_len]u8, my_id: *const identity.Identity, m1: []const u8, eph_seed: [32]u8) Error!Responder {
        if (m1.len != m1_len) return error.BadLength;

        var h0: [32]u8 = undefined;
        Blake2s256.hash(domain, &h0, .{});

        const e1_public: [32]u8 = m1[0..32].*;

        // транскрипт покрывает весь m1 (включая enc_pk инициатора):
        // подмена любого байта меняет ключи и роняет подпись в m3
        var self = Responder{
            .h = hashParts(&[_][]const u8{ &h0, m1 }),
            .ck = h0,
            .k2 = undefined,
            .e2_secret = undefined,
            .my_id = my_id,
        };

        const e2 = X25519.KeyPair.generateDeterministic(eph_seed);
        self.e2_secret = e2.secret_key;

        // h2 = H(h1||e2)
        self.h = hashParts(&[_][]const u8{ &self.h, &e2.public_key });

        // ee = X25519(e_r, e_i) -> k1
        const ee = X25519.scalarmult(self.e2_secret, e1_public) catch return error.Tampered;
        const k1 = mixKey(&self.ck, &ee);

        // m2: e2_pub || box(resp_enc_pk || sig_r), ad = h2
        var payload: [payload_len]u8 = undefined;
        payload[0..32].* = my_id.enc_public;
        try signTranscript(my_id, self.h, payload[32..payload_len]);
        out_m2[0..32].* = e2.public_key;
        aead.seal(out_m2[32..], &payload, k1, aead.nonceFor(0), &self.h);
        @memset(&payload, 0);

        // транскрипт после m2
        self.h = hashParts(&[_][]const u8{ &self.h, out_m2[32..] });

        // es = X25519(s_r, e_i) -> k2 (ключ статики инициатора в m3)
        const es = X25519.scalarmult(my_id.enc_secret, e1_public) catch return error.Tampered;
        self.k2 = mixKey(&self.ck, &es);

        return self;
    }

    /// Обрабатывает m3. peer_sign_public == null — режим pending-join:
    /// подпись НЕ проверяется (контакт неизвестен), личность доказывается
    /// JOIN-конвертом поверх сессии; peer_enc_public == null — то же для
    /// сверки статики. Для известного контакта оба значения передаются из
    /// bundle. Возвращает сессионные ключи.
    pub fn recv3(self: *Responder, m3: []const u8, peer_sign_public: ?[32]u8, peer_enc_public: ?[32]u8) Error!SessionKeys {
        if (m3.len != m3_len) return error.BadLength;

        // открыть box2: init_enc_pk || sig_i (ad = h3)
        var payload: [payload_len]u8 = undefined;
        aead.open(&payload, m3, self.k2, aead.nonceFor(1), &self.h) catch return error.Tampered;
        const init_enc_public: [32]u8 = payload[0..32].*;
        const sig_i: [sig_len]u8 = payload[32..payload_len].*;
        @memset(&payload, 0);

        // статический ключ обязан совпадать с известным bundle контакта
        if (peer_enc_public) |expected| {
            if (!std.mem.eql(u8, &init_enc_public, &expected)) return error.KeyMismatch;
        }

        // подпись инициатора над транскриптом h3
        if (peer_sign_public) |pk| {
            try identity.Identity.verify(pk, &self.h, sig_i);
        }

        // транскрипт после m3
        self.h = hashParts(&[_][]const u8{ &self.h, m3 });

        // se = X25519(s_r, s_i) -> ck
        const se = X25519.scalarmult(self.e2_secret, init_enc_public) catch return error.Tampered;
        _ = mixKey(&self.ck, &se);

        return finishKeys(self.ck, self.h, .responder);
    }
};

const Side = enum { initiator, responder };

/// Разворачивает финальный ck в зеркальные пары ключей.
fn finishKeys(ck: [32]u8, transcript: [32]u8, side: Side) SessionKeys {
    var okm: [64]u8 = undefined;
    HkdfSha256.expand(&okm, finish_info, ck);
    const k_i2r = okm[0..32].*; // поток инициатор -> ответчик
    const k_r2i = okm[32..64].*; // поток ответчик -> инициатор
    @memset(&okm, 0);

    return switch (side) {
        .initiator => .{ .send_key = k_i2r, .recv_key = k_r2i, .transcript = transcript },
        .responder => .{ .send_key = k_r2i, .recv_key = k_i2r, .transcript = transcript },
    };
}

// --- тесты ---

/// Фиксированные сиды: полный рукопожатие детерминистичен.
const seed_i = 0xA5;
const seed_r = 0x5A;
const eph_i_seed: [32]u8 = @splat(0x11);
const eph_r_seed: [32]u8 = @splat(0x22);

fn testIdentity(fill: u8) !identity.Identity {
    const seed: [32]u8 = @splat(fill);
    return identity.Identity.fromSeed(seed);
}

fn runHandshake() !struct { init_keys: SessionKeys, resp_keys: SessionKeys, m1: [m1_len]u8, m2: [m2_len]u8, m3: [m3_len]u8 } {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    const init_keys = try init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);
    const resp_keys = try resp.recv3(&m3, id_i.sign_public, id_i.enc_public);

    return .{ .init_keys = init_keys, .resp_keys = resp_keys, .m1 = m1, .m2 = m2, .m3 = m3 };
}

test "handshake: полный рукопожатие, ключи зеркальны" {
    const hs = try runHandshake();

    try std.testing.expectEqualSlices(u8, &hs.init_keys.send_key, &hs.resp_keys.recv_key);
    try std.testing.expectEqualSlices(u8, &hs.init_keys.recv_key, &hs.resp_keys.send_key);
    try std.testing.expectEqualSlices(u8, &hs.init_keys.transcript, &hs.resp_keys.transcript);
    try std.testing.expect(!std.mem.eql(u8, &hs.init_keys.send_key, &hs.init_keys.recv_key));
}

test "handshake: трафик сессионными ключами" {
    const hs = try runHandshake();
    const plain = "первый кадр";
    const nonce = aead.nonceFor(0);

    var buf: [plain.len + aead.tag_length]u8 = undefined;
    aead.seal(&buf, plain, hs.init_keys.send_key, nonce, &hs.init_keys.transcript);

    var out: [plain.len]u8 = undefined;
    try aead.open(&out, &buf, hs.resp_keys.recv_key, nonce, &hs.resp_keys.transcript);
    try std.testing.expectEqualSlices(u8, plain, &out);
}

test "handshake: детерминизм при тех же сидах" {
    const a = try runHandshake();
    const b = try runHandshake();
    try std.testing.expectEqualSlices(u8, &a.m1, &b.m1);
    try std.testing.expectEqualSlices(u8, &a.m2, &b.m2);
    try std.testing.expectEqualSlices(u8, &a.m3, &b.m3);
    try std.testing.expectEqualSlices(u8, &a.init_keys.send_key, &b.init_keys.send_key);
    try std.testing.expectEqualSlices(u8, &a.init_keys.recv_key, &b.init_keys.recv_key);
    try std.testing.expectEqualSlices(u8, &a.init_keys.transcript, &b.init_keys.transcript);

    // другие эфемеральные сиды -> другие ключи при тех же личностях
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1a: [m1_len]u8 = undefined;
    var m1b: [m1_len]u8 = undefined;
    var m2a: [m2_len]u8 = undefined;
    var m2b: [m2_len]u8 = undefined;
    var m3a: [m3_len]u8 = undefined;
    var m3b: [m3_len]u8 = undefined;

    const eph_alt: [32]u8 = @splat(0x33);
    var ia = Initiator.start(&m1a, &id_i, eph_i_seed);
    var ra = try Responder.recv1(&m2a, &id_r, &m1a, eph_r_seed);
    const ka = try ia.recv2(&m3a, &m2a, id_r.sign_public, id_r.enc_public);
    _ = try ra.recv3(&m3a, id_i.sign_public, id_i.enc_public);

    var ib = Initiator.start(&m1b, &id_i, eph_alt);
    var rb = try Responder.recv1(&m2b, &id_r, &m1b, eph_alt);
    const kb = try ib.recv2(&m3b, &m2b, id_r.sign_public, id_r.enc_public);
    _ = try rb.recv3(&m3b, id_i.sign_public, id_i.enc_public);

    try std.testing.expect(!std.mem.eql(u8, &ka.send_key, &kb.send_key));
    try std.testing.expect(!std.mem.eql(u8, &ka.transcript, &kb.transcript));
}

test "handshake: битый байт в m2 -> Tampered" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    _ = &resp;

    // порча шифротекста box1
    m2[m2.len - 1] ^= 0x01;
    try std.testing.expectError(error.Tampered, init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public));

    // порча e2_pub -> другой ee -> box1 не открывается
    m2[m2.len - 1] ^= 0x01;
    m2[0] ^= 0x01;
    try std.testing.expectError(error.Tampered, init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public));
}

test "handshake: чужой sign_pk у инициатора -> BadSignature" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();
    var id_x = try testIdentity(0xEE);
    defer id_x.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    _ = &resp;

    // инициатор сверяет sig_r не с тем ключом
    try std.testing.expectError(error.BadSignature, init.recv2(&m3, &m2, id_x.sign_public, id_r.enc_public));
}

test "handshake: подмена sign_pk у ответчика -> BadSignature" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();
    var id_x = try testIdentity(0x77);
    defer id_x.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    const keys = try init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);

    // ответчик сверяет sig_i не с тем ключом
    try std.testing.expectError(error.BadSignature, resp.recv3(&m3, id_x.sign_public, id_i.enc_public));

    // контроль: с правильным ключом всё проходит
    var init2 = Initiator.start(&m1, &id_i, eph_i_seed);
    var resp2 = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    const keys2 = try init2.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);
    const keys3 = try resp2.recv3(&m3, id_i.sign_public, id_i.enc_public);
    try std.testing.expectEqualSlices(u8, &keys.send_key, &keys2.send_key);
    try std.testing.expectEqualSlices(u8, &keys3.send_key, &keys.recv_key);
}

test "handshake: BadLength" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    try std.testing.expectError(error.BadLength, Responder.recv1(&m2, &id_r, m1[0 .. m1.len - 1], eph_r_seed));

    var init = Initiator.start(&m1, &id_i, eph_i_seed);
    _ = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    try std.testing.expectError(error.BadLength, init.recv2(&m3, m2[0 .. m2.len - 1], id_r.sign_public, id_r.enc_public));

    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    _ = try init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);
    try std.testing.expectError(error.BadLength, resp.recv3(m3[0 .. m3.len - 2], id_i.sign_public, id_i.enc_public));
}

test "handshake: чужая статика в боксе -> KeyMismatch" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();
    var id_x = try testIdentity(0xEE);
    defer id_x.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);

    // инициатор ждёт статику id_x, а пришла id_r
    try std.testing.expectError(error.KeyMismatch, init.recv2(&m3, &m2, id_r.sign_public, id_x.enc_public));

    // контрольный m3 (валидный путь), затем ответчик ждёт статику id_x,
    // а в m3 — id_i
    var init2 = Initiator.start(&m1, &id_i, eph_i_seed);
    _ = try init2.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);
    try std.testing.expectError(error.KeyMismatch, resp.recv3(&m3, id_i.sign_public, id_x.enc_public));

    // null (pending-join): сверка не делается, всё проходит
    var resp2 = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    _ = try resp2.recv3(&m3, null, null);
}
