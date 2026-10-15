//! Симметричный рэтчет: шаг сообщения эволюционирует цепочку
//! (msg_key = HKDF-Expand(ck, "shopot-msg-v3" || u64 LE counter),
//! затем ck = HMAC-SHA256(ck, 0x02)), DH-шаг пересоздаёт обе цепочки из
//! X25519 (root = HKDF(shared, "shopot-ratchet-v3")). Приём разделён на
//! peekRecv (вывод ключа ОЖИДАЕМОГО кадра без сдвига цепочки) и commitRecv
//! (сдвиг после успешной расшифровки) — по Double Ratchet spec §3.5/§8.10.
//! Направления делятся
//! детерминированно: сторона с лексикографически меньшим публичным ключом
//! шлёт по цепочке HMAC(root, 0x03) и принимает по HMAC(root, 0x04),
//! противоположная — наоборот; обе стороны получают одинаковые значения
//! chain_send/chain_recv, зеркальные по направлениям.

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;

const msg_info = "shopot-msg-v3";
const ratchet_salt = "shopot-ratchet-v3";

/// Ошибки рэтчета: вырожденный публичный ключ удалённой стороны.
pub const Error = error{BadRemoteKey};

pub const Ratchet = struct {
    /// Цепочка исходящих сообщений.
    chain_send: [32]u8,
    /// Цепочка входящих сообщений.
    chain_recv: [32]u8,
    /// Счётчик следующего исходящего сообщения (уходит в nonce AEAD).
    send_counter: u64,
    /// Счётчик следующего входящего сообщения.
    recv_counter: u64,

    /// Собирает рэтчет из начальных цепочек (обычно из handshake).
    pub fn init(chain_send: [32]u8, chain_recv: [32]u8) Ratchet {
        return .{
            .chain_send = chain_send,
            .chain_recv = chain_recv,
            .send_counter = 0,
            .recv_counter = 0,
        };
    }

    /// Выводит ключ исходящего сообщения в `msg_key` и возвращает счётчик
    /// nonce для aead.nonceFor; затем сдвигает цепочку отправки.
    pub fn stepSend(self: *Ratchet, msg_key: *[32]u8) u64 {
        const counter = self.send_counter;
        self.send_counter += 1;
        messageKey(self.chain_send, counter, msg_key);
        stepChain(&self.chain_send);
        return counter;
    }

    /// Выводит ключ ОЖИДАЕМОГО входящего сообщения в `msg_key` и возвращает
    /// его счётчик, НЕ сдвигая цепочку приёма: цепочка обязана сдвигаться
    /// только после УСПЕШНОЙ расшифровки кадра (commitRecv), иначе один
    /// битый кадр навсегда рассинхронизирует стороны (см. spec Double
    /// Ratchet, §3.5: ключ выводится под конкретный номер сообщения).
    /// Зеркален stepSend при том же состоянии цепочки.
    pub fn peekRecv(self: *const Ratchet, msg_key: *[32]u8) u64 {
        messageKey(self.chain_recv, self.recv_counter, msg_key);
        return self.recv_counter;
    }

    /// Сдвигает цепочку приёма и счётчик после успешной расшифровки кадра,
    /// выведенного через peekRecv. Повторный вызов без peek — ошибка
    /// программирования (рассинхронизация), поэтому сдвиг необратим.
    pub fn commitRecv(self: *Ratchet) void {
        stepChain(&self.chain_recv);
        self.recv_counter += 1;
    }

    /// DH-шаг: обе цепочки пересоздаются из X25519(`own_enc_sk`, `new_remote_pub`),
    /// счётчики сбрасываются в 0. Направление "03" назначается стороне с меньшим
    /// публичным ключом (детерминированное правило, одинаковое у обеих сторон),
    /// поэтому chain_send одной стороны всегда совпадает с chain_recv другой.
    pub fn dhStep(self: *Ratchet, new_remote_pub: [32]u8, own_enc_sk: [32]u8) Error!void {
        var shared = X25519.scalarmult(own_enc_sk, new_remote_pub) catch return error.BadRemoteKey;
        var root = HkdfSha256.extract(ratchet_salt, &shared);
        std.crypto.secureZero(u8, &shared);

        const s3 = [_]u8{0x03};
        const s4 = [_]u8{0x04};
        var c3: [32]u8 = undefined;
        var c4: [32]u8 = undefined;
        HmacSha256.create(&c3, &s3, &root);
        HmacSha256.create(&c4, &s4, &root);
        std.crypto.secureZero(u8, &root);

        const own_public = X25519.recoverPublicKey(own_enc_sk);
        if (std.mem.order(u8, &own_public, &new_remote_pub) != .gt) {
            self.chain_send = c3;
            self.chain_recv = c4;
        } else {
            self.chain_send = c4;
            self.chain_recv = c3;
        }
        @memset(&c3, 0);
        @memset(&c4, 0);

        self.send_counter = 0;
        self.recv_counter = 0;
    }
};

/// msg_key = HKDF-Expand(chain, "shopot-msg-v3" || u64 LE counter).
fn messageKey(chain: [32]u8, counter: u64, out: *[32]u8) void {
    var info: [msg_info.len + 8]u8 = undefined;
    @memcpy(info[0..msg_info.len], msg_info);
    std.mem.writeInt(u64, info[msg_info.len..][0..8], counter, .little);
    HkdfSha256.expand(out, &info, chain);
}

/// ck = HMAC-SHA256(ck, 0x02), старое значение обнуляется.
fn stepChain(chain: *[32]u8) void {
    var next: [32]u8 = undefined;
    const input = [_]u8{0x02};
    HmacSha256.create(&next, &input, chain);
    std.crypto.secureZero(u8, chain);
    chain.* = next;
}

test "ratchet: эволюция ключей и счётчиков" {
    var r = Ratchet.init(@splat(1), @splat(2));

    var k0: [32]u8 = undefined;
    var k1: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    const c0 = r.stepSend(&k0);
    const c1 = r.stepSend(&k1);
    const c2 = r.stepSend(&k2);

    try std.testing.expectEqual(@as(u64, 0), c0);
    try std.testing.expectEqual(@as(u64, 1), c1);
    try std.testing.expectEqual(@as(u64, 2), c2);
    try std.testing.expect(!std.mem.eql(u8, &k0, &k1));
    try std.testing.expect(!std.mem.eql(u8, &k1, &k2));
    try std.testing.expect(!std.mem.eql(u8, &k0, &k2));

    // цепочка приёма независима от цепочки отправки
    var rk0: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u64, 0), r.peekRecv(&rk0));
    r.commitRecv();
    try std.testing.expect(!std.mem.eql(u8, &k0, &rk0));
}

test "ratchet: peekRecv не сдвигает цепочку до commitRecv" {
    var a = Ratchet.init(@splat(3), @splat(4));

    // два peek без commit: один и тот же ключ и счётчик (кадр можно
    // попытаться расшифровать повторно, цепочка не поехала)
    var k1: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u64, 0), a.peekRecv(&k1));
    try std.testing.expectEqual(@as(u64, 0), a.peekRecv(&k2));
    try std.testing.expectEqualSlices(u8, &k1, &k2);

    // «расшифровка не удалась» — цепочка не сдвинута, следующий кадр
    // выводится из того же состояния
    var k3: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u64, 0), a.peekRecv(&k3));
    try std.testing.expectEqualSlices(u8, &k1, &k3);

    // успешная расшифровка: commit сдвигает цепочку и счётчик
    a.commitRecv();
    var k4: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u64, 1), a.peekRecv(&k4));
    try std.testing.expect(!std.mem.eql(u8, &k1, &k4));
    // счётчик отправки не тронут: peek/commit не влияют на исходящие
    try std.testing.expectEqual(@as(u64, 0), a.send_counter);
}

test "ratchet: peekRecv+commitRecv зеркальны stepSend" {
    var a = Ratchet.init(@splat(3), @splat(4));
    var b = Ratchet.init(@splat(4), @splat(3)); // встречные цепочки

    var mk: [32]u8 = undefined;
    var rk: [32]u8 = undefined;
    const sc = a.stepSend(&mk);
    const rc = b.peekRecv(&rk);
    b.commitRecv();

    try std.testing.expectEqual(sc, rc);
    try std.testing.expectEqualSlices(u8, &mk, &rk);

    var mk2: [32]u8 = undefined;
    var rk2: [32]u8 = undefined;
    const sc2 = a.stepSend(&mk2);
    const rc2 = b.peekRecv(&rk2);
    b.commitRecv();
    try std.testing.expectEqual(sc2, rc2);
    try std.testing.expectEqualSlices(u8, &mk2, &rk2);
    try std.testing.expect(!std.mem.eql(u8, &mk, &mk2));
}

test "ratchet: зеркальность сторон после dhStep" {
    var sk_a: [32]u8 = undefined;
    var sk_b: [32]u8 = undefined;
    for (&sk_a, 0..) |*byte, i| byte.* = @truncate(i *% 5 +% 1);
    for (&sk_b, 0..) |*byte, i| byte.* = @truncate(i *% 9 +% 7);

    const pk_a = X25519.recoverPublicKey(sk_a);
    const pk_b = X25519.recoverPublicKey(sk_b);

    var a = Ratchet.init(@splat(1), @splat(1));
    var b = Ratchet.init(@splat(2), @splat(2));

    try a.dhStep(pk_b, sk_a);
    try b.dhStep(pk_a, sk_b);

    // у обеих сторон одинаковые встречные цепочки
    try std.testing.expectEqualSlices(u8, &a.chain_send, &b.chain_recv);
    try std.testing.expectEqualSlices(u8, &a.chain_recv, &b.chain_send);
    try std.testing.expectEqual(@as(u64, 0), a.send_counter);
    try std.testing.expectEqual(@as(u64, 0), b.recv_counter);

    // ключи сообщений сходятся после dhStep
    var mk: [32]u8 = undefined;
    var rk: [32]u8 = undefined;
    const sc = a.stepSend(&mk);
    const rc = b.peekRecv(&rk);
    b.commitRecv();
    try std.testing.expectEqual(sc, rc);
    try std.testing.expectEqualSlices(u8, &mk, &rk);
}

test "ratchet: цепочки после dhStep отличаются от прежних" {
    const sk_a: [32]u8 = @splat(1);
    const sk_b: [32]u8 = @splat(2);
    const pk_b = X25519.recoverPublicKey(sk_b);

    var a = Ratchet.init(@splat(1), @splat(1));
    const old_send = a.chain_send;
    try a.dhStep(pk_b, sk_a);
    try std.testing.expect(!std.mem.eql(u8, &old_send, &a.chain_send));
    const after_first = a.chain_send;

    // повторный dhStep с новой удалённой парой -> снова новые цепочки,
    // счётчики снова с нуля
    const sk_c = [_]u8{9} ++ @as([31]u8, @splat(4));
    const pk_c = X25519.recoverPublicKey(sk_c);
    try a.dhStep(pk_c, sk_a);
    try std.testing.expect(!std.mem.eql(u8, &after_first, &a.chain_send));
    try std.testing.expect(!std.mem.eql(u8, &after_first, &a.chain_recv));
    try std.testing.expectEqual(@as(u64, 0), a.send_counter);
    try std.testing.expectEqual(@as(u64, 0), a.recv_counter);
}

test "ratchet: вырожденный ключ -> BadRemoteKey" {
    var a = Ratchet.init(@splat(1), @splat(1));
    const zero_pub: [32]u8 = @splat(0);
    try std.testing.expectError(error.BadRemoteKey, a.dhStep(zero_pub, @splat(3)));
}
