//! One encrypted session with one contact over one transport connection.
//! Flow: transport connect -> XX handshake (both identities authenticated by
//! Ed25519 signatures over the transcript) -> traffic keys -> caller-provided
//! stream wrapper (obfuscated AEAD) -> framed envelopes. TEXT payloads are
//! additionally sealed by the per-message ratchet: two independent crypto
//! layers, each with its own forward secrecy.
const std = @import("std");
const interfaces = @import("interfaces.zig");
const handshake = @import("../crypto/handshake.zig");
const ratchet_mod = @import("../crypto/ratchet.zig");
const kdf = @import("../crypto/kdf.zig");
const aead = @import("../crypto/aead.zig");
const identity_mod = @import("../crypto/identity.zig");
const envelope = @import("../proto/envelope.zig");

pub const SessionError = error{
    HandshakeFailed,
    BadSignature,
    Tampered,
    Closed,
    OutOfSpace,
    TooBig,
};

pub const HandshakeRole = enum { initiator, responder };

/// The engine wraps the raw transport into the encrypted stream once the
/// handshake yields the traffic keys. Keeps session.zig free of net/ imports.
pub const WrapFn = *const fn (
    ctx: *anyopaque,
    raw: interfaces.Conn,
    keys: handshake.SessionKeys,
    alloc: std.mem.Allocator,
) anyerror!interfaces.Conn;

pub const Events = struct {
    ctx: *anyopaque,
    onEnvelope: *const fn (ctx: *anyopaque, env: envelope.Envelope) void,
    onClosed: *const fn (ctx: *anyopaque) void,
};

const sealed_tag: u8 = 0xA1; // ratchet-sealed TEXT frame marker

pub const Session = struct {
    conn: interfaces.Conn,
    ratchet: ratchet_mod.Ratchet,
    keys: handshake.SessionKeys,
    ev: Events,
    send_mu: std.Io.Mutex = .init,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    rx_thread: ?std.Thread = null,
    alloc: std.mem.Allocator,
    io: std.Io,

    pub fn establish(
        alloc: std.mem.Allocator,
        conn: interfaces.Conn,
        role: HandshakeRole,
        my_id: *const identity_mod.Identity,
        peer_bundle: [64]u8,
        eph_seed: [32]u8,
        wrap_ctx: *anyopaque,
        wrap: WrapFn,
        ev: Events,
        io: std.Io,
    ) SessionError!*Session {
        var keys: handshake.SessionKeys = undefined;
        switch (role) {
            .initiator => {
                var m1: [handshake.m1_len]u8 = undefined;
                var m2: [handshake.m2_len]u8 = undefined;
                var m3: [handshake.m3_len]u8 = undefined;
                var m1f: [2 + handshake.m1_len]u8 = undefined;
                var m3f: [2 + handshake.m3_len]u8 = undefined;
                var hs = handshake.Initiator.start(&m1, my_id, eph_seed);
                writeFrame(conn, &m1f, &m1) catch return SessionError.Closed;
                _ = readFrame(conn, &m2) catch return SessionError.Closed;
                keys = hs.recv2(&m3, &m2, peer_bundle[32..64].*, peer_bundle[0..32].*) catch |e| switch (e) {
                    error.BadSignature => return SessionError.BadSignature,
                    error.KeyMismatch => return SessionError.BadSignature,
                    else => return SessionError.HandshakeFailed,
                };
                writeFrame(conn, &m3f, &m3) catch return SessionError.Closed;
            },
            .responder => {
                var m1: [handshake.m1_len]u8 = undefined;
                var m2: [handshake.m2_len]u8 = undefined;
                var m3: [handshake.m3_len]u8 = undefined;
                var m2f: [2 + handshake.m2_len]u8 = undefined;
                _ = readFrame(conn, &m1) catch return SessionError.Closed;
                var hs = handshake.Responder.recv1(&m2, my_id, &m1, eph_seed) catch
                    return SessionError.HandshakeFailed;
                writeFrame(conn, &m2f, &m2) catch return SessionError.Closed;
                _ = readFrame(conn, &m3) catch return SessionError.Closed;
                keys = hs.recv3(&m3, peer_bundle[32..64].*, peer_bundle[0..32].*) catch |e| switch (e) {
                    error.BadSignature => return SessionError.BadSignature,
                    error.KeyMismatch => return SessionError.BadSignature,
                    else => return SessionError.HandshakeFailed,
                };
            },
        }

        const wrapped = wrap(wrap_ctx, conn, keys, alloc) catch return SessionError.OutOfSpace;

        // Ratchet chains: label 1 is A->B, label 2 is B->A. The initiator maps
        // send->1/recv->2, the responder the mirror, so the send chain of one
        // side is byte-identical to the recv chain of the other.
        var chain_send: [32]u8 = undefined;
        var chain_recv: [32]u8 = undefined;
        switch (role) {
            .initiator => {
                kdf.expand(keys.transcript, "shopot-chain-1", &chain_send);
                kdf.expand(keys.transcript, "shopot-chain-2", &chain_recv);
            },
            .responder => {
                kdf.expand(keys.transcript, "shopot-chain-2", &chain_send);
                kdf.expand(keys.transcript, "shopot-chain-1", &chain_recv);
            },
        }

        const self = alloc.create(Session) catch return SessionError.OutOfSpace;
        errdefer alloc.destroy(self);
        self.* = .{
            .conn = wrapped,
            .ratchet = ratchet_mod.Ratchet.init(chain_send, chain_recv),
            .keys = keys,
            .ev = ev,
            .alloc = alloc,
            .io = io,
        };
        self.rx_thread = std.Thread.spawn(.{}, rxLoop, .{self}) catch {
            wrapped.close();
            alloc.destroy(self);
            return SessionError.OutOfSpace;
        };
        return self;
    }

    /// Responder с готовым (уже прочитанным из транспорта) m1: вызывающий
    /// сам решает, чей это контакт, по любому признаку из m1 (например,
    /// enc_pk = m1[32..64] = bundle[0..32]) и возвращает cid или null.
    /// cid используется только как метка для вызывающего (события сессии
    /// не зависят от него), поэтому ядро остаётся независимым от app.
    pub const IdentifyResult = struct {
        /// enc_pk найденного контакта (bundle[0..32]) — сверка статики в m3.
        enc_pk: [32]u8,
        /// sign_pk найденного контакта (bundle[32..64]); null — не наш контакт.
        sign_pk: [32]u8,
    };

    pub const IdentifyFn = *const fn (ctx: *anyopaque, enc_pk: [32]u8) ?IdentifyResult;

    pub fn establishIdentified(
        alloc: std.mem.Allocator,
        conn: interfaces.Conn,
        m1: []const u8,
        my_id: *const identity_mod.Identity,
        eph_seed: [32]u8,
        identify: IdentifyFn,
        identify_ctx: *anyopaque,
        wrap_ctx: *anyopaque,
        wrap: WrapFn,
        ev: Events,
        io: std.Io,
    ) SessionError!?*Session {
        if (m1.len != handshake.m1_len) return SessionError.HandshakeFailed;
        const enc_pk: [32]u8 = m1[32..64].*;
        const found = identify(identify_ctx, enc_pk) orelse return null;
        var m2: [handshake.m2_len]u8 = undefined;
        var m3: [handshake.m3_len]u8 = undefined;
        var m2f: [2 + handshake.m2_len]u8 = undefined;
        var hs = handshake.Responder.recv1(&m2, my_id, m1[0..handshake.m1_len], eph_seed) catch
            return SessionError.HandshakeFailed;
        writeFrame(conn, &m2f, &m2) catch return SessionError.Closed;
        _ = readFrame(conn, &m3) catch return SessionError.Closed;
        const keys = hs.recv3(&m3, found.sign_pk, found.enc_pk) catch |e| switch (e) {
            error.BadSignature => return SessionError.BadSignature,
            error.KeyMismatch => return SessionError.BadSignature,
            else => return SessionError.HandshakeFailed,
        };
        return finishEstablish(alloc, conn, keys, .responder, wrap_ctx, wrap, ev, io);
    }

    /// Рукопожатие без опознания (pending-join): инициатор неизвестен,
    /// подпись m3 не проверяется — личность и право на подключение
    /// доказываются первым конвертом JOIN поверх поднятой сессии.
    /// Вызывающий обязан закрыть сессию, если валидный JOIN не пришёл.
    pub fn establishPending(
        alloc: std.mem.Allocator,
        conn: interfaces.Conn,
        m1: []const u8,
        my_id: *const identity_mod.Identity,
        eph_seed: [32]u8,
        wrap_ctx: *anyopaque,
        wrap: WrapFn,
        ev: Events,
        io: std.Io,
    ) SessionError!*Session {
        if (m1.len != handshake.m1_len) return SessionError.HandshakeFailed;
        var m2: [handshake.m2_len]u8 = undefined;
        var m3: [handshake.m3_len]u8 = undefined;
        var m2f: [2 + handshake.m2_len]u8 = undefined;
        var hs = handshake.Responder.recv1(&m2, my_id, m1[0..handshake.m1_len], eph_seed) catch
            return SessionError.HandshakeFailed;
        writeFrame(conn, &m2f, &m2) catch return SessionError.Closed;
        _ = readFrame(conn, &m3) catch return SessionError.Closed;
        const keys = hs.recv3(&m3, null, null) catch return SessionError.HandshakeFailed;
        return finishEstablish(alloc, conn, keys, .responder, wrap_ctx, wrap, ev, io);
    }

    /// Общий хвост establish: wrap, ratchet-цепочки, Session, rx-поток.
    fn finishEstablish(
        alloc: std.mem.Allocator,
        conn: interfaces.Conn,
        keys: handshake.SessionKeys,
        role: HandshakeRole,
        wrap_ctx: *anyopaque,
        wrap: WrapFn,
        ev: Events,
        io: std.Io,
    ) SessionError!*Session {
        const wrapped = wrap(wrap_ctx, conn, keys, alloc) catch return SessionError.OutOfSpace;
        var chain_send: [32]u8 = undefined;
        var chain_recv: [32]u8 = undefined;
        switch (role) {
            .initiator => {
                kdf.expand(keys.transcript, "shopot-chain-1", &chain_send);
                kdf.expand(keys.transcript, "shopot-chain-2", &chain_recv);
            },
            .responder => {
                kdf.expand(keys.transcript, "shopot-chain-2", &chain_send);
                kdf.expand(keys.transcript, "shopot-chain-1", &chain_recv);
            },
        }
        const self = alloc.create(Session) catch return SessionError.OutOfSpace;
        errdefer alloc.destroy(self);
        self.* = .{
            .conn = wrapped,
            .ratchet = ratchet_mod.Ratchet.init(chain_send, chain_recv),
            .keys = keys,
            .ev = ev,
            .alloc = alloc,
            .io = io,
        };
        self.rx_thread = std.Thread.spawn(.{}, rxLoop, .{self}) catch {
            wrapped.close();
            alloc.destroy(self);
            return SessionError.OutOfSpace;
        };
        return self;
    }

    /// TEXT: ratchet-sealed (layer 2) before the obfuscated stream (layer 1).
    /// msg_id/ts_ms генерируются здесь — для прямых вызовов и тестов.
    pub fn sendText(self: *Session, body: []const u8) SessionError!void {
        if (body.len > envelope.max_text_body) return SessionError.TooBig;
        var msg_id: [16]u8 = undefined;
        self.fillRandom(&msg_id);
        var ts_buf: [8]u8 = undefined;
        self.io.random(&ts_buf);
        const ts_ms: u64 = std.mem.readInt(u64, &ts_buf, .little) % 100_000_000_000_000;
        return self.sendSealedText(.{ .text = .{
            .msg_id = msg_id,
            .ts_ms = ts_ms,
            .body = body,
        } });
    }

    /// Ratchet-запечатанный TEXT (слой 2 поверх транспортного AEAD).
    /// msg_id/ts_ms берутся ИЗ КОНВЕРТА вызывающего: движку они нужны для
    /// дедупа, ACK и outbox — генерить их заново нельзя (рассинхрон
    /// статусов доставки). Слой рэтчета даёт per-message forward secrecy:
    /// каждое сообщение запечатано собственным ключом, цепочка уходит
    /// вперёд независимо от транспортного ключа.
    pub fn sendSealedText(self: *Session, env: envelope.Envelope) SessionError!void {
        return self.sendSealedTexts(&.{env});
    }

    /// Пачка запечатанных TEXT: [len][sealed]||[len][sealed]… уходит ОДНИМ
    /// conn.writeAll — обф-слой кладёт пачку мелких конвертов в один
    /// паддированный кадр вместо кадра на каждый (коалесценция мелких
    /// конвертов, ROADMAP P1: оверхед 128+26 байт на конверт → на пачку).
    /// Приёмник разбирает поток кадр за кадром через leftover-буфер
    /// ObfReader — формат провода НЕ меняется. Сбой пачки оставляет записи
    /// outbox нетронутыми, повтор идемпотентен дедупом на приёме.
    pub fn sendSealedTexts(self: *Session, envs: []const envelope.Envelope) SessionError!void {
        if (envs.len == 0) return;
        // 16356 = старший obf-класс 16384 минус оверхед кадра 26 и метка
        // паддинга 2 (net/obfuscate.zig; импорт net из core запрещён —
        // значение продублировано осознанно, как таблица бакетов)
        const batch_max: usize = 16356;
        var batch: [batch_max]u8 = undefined;
        var used: usize = 0;
        self.send_mu.lockUncancelable(self.io);
        defer self.send_mu.unlock(self.io);
        for (envs) |env| {
            var enc: [envelope.max_encoded_len]u8 = undefined;
            const plain = envelope.encode(&enc, env) catch return SessionError.TooBig;
            const frame_len: usize = 9 + plain.len + aead.tag_length;
            if (2 + frame_len > batch.len) return SessionError.TooBig;
            if (used > 0 and used + 2 + frame_len > batch.len) {
                // буфер полон: флеш накопленного, конверт — в следующий
                self.conn.writeAll(batch[0..used]) catch return SessionError.Closed;
                used = 0;
            }
            // ratchet-запечатывание прямо в batch (2 байта заголовка кадра
            // спереди): один conn.writeAll на всю пачку
            var msg_key: [32]u8 = undefined;
            const counter = self.ratchet.stepSend(&msg_key);
            batch[used + 2] = sealed_tag;
            std.mem.writeInt(u64, batch[used + 3 ..][0..8], counter, .little);
            const nonce = aead.nonceFor(counter);
            aead.seal(batch[used + 11 ..], plain, msg_key, nonce, batch[used + 2 ..][0..9]);
            std.mem.writeInt(u16, batch[used..][0..2], @intCast(frame_len), .little);
            used += 2 + frame_len;
        }
        if (used > 0) self.conn.writeAll(batch[0..used]) catch return SessionError.Closed;
    }

    /// Everything else rides the transport layer only (presence, reactions,
    /// call signaling and audio have their own per-call keys).
    /// Секрет звонка: HKDF из транскрипта рукопожатия + call_id. Обе стороны
    /// одной сессии выводят одинаковое значение, разные звонки — разные ключи.
    pub fn callSecret(self: *Session, call_id: [16]u8) [32]u8 {
        var info: [16 + "shopot-call-secret".len]u8 = undefined;
        info[0..16].* = call_id;
        @memcpy(info[16..], "shopot-call-secret");
        var out: [32]u8 = undefined;
        kdf.expand(self.keys.transcript, &info, &out);
        return out;
    }

    pub fn sendEnvelope(self: *Session, env: envelope.Envelope) SessionError!void {
        // кодируем со сдвигом 2: [hdr][envelope] уходит одним writeAll
        // (один obf-кадр на конверт вместо двух)
        var buf: [envelope.max_encoded_len + 2]u8 = undefined;
        const plain = envelope.encode(buf[2..], env) catch return SessionError.TooBig;
        std.mem.writeInt(u16, buf[0..2], @intCast(plain.len), .little);
        self.send_mu.lockUncancelable(self.io);
        defer self.send_mu.unlock(self.io);
        self.conn.writeAll(buf[0 .. 2 + plain.len]) catch return SessionError.Closed;
    }

    pub fn close(self: *Session) void {
        if (self.running.swap(false, .seq_cst)) {
            self.conn.close();
            if (self.rx_thread) |t| t.join();
            self.rx_thread = null;
            self.ev.onClosed(self.ev.ctx);
        }
    }

    fn rxLoop(self: *Session) void {
        var buf: [envelope.max_encoded_len + 64]u8 = undefined;
        while (self.running.load(.seq_cst)) {
            const n = readFrame(self.conn, &buf) catch break;
            if (n == 0) break;
            var env: envelope.Envelope = undefined;
            if (buf[0] == sealed_tag) {
                if (n < 10) continue;
                const counter = std.mem.readInt(u64, buf[1..9], .little);
                var msg_key: [32]u8 = undefined;
                self.send_mu.lockUncancelable(self.io);
                // вывод ключа БЕЗ сдвига цепочки: счётчик обязан совпасть
                // с ожидаемым (повтор/перестановка — кадр отбрасывается),
                // цепочка сдвигается только после успешной расшифровки.
                // Раньше stepRecv сдвигал цепочку ДО open: один битый кадр
                // навсегда рассинхронизировал стороны — все последующие
                // TEXT молча терялись.
                const expected = self.ratchet.peekRecv(&msg_key);
                if (counter != expected) {
                    self.send_mu.unlock(self.io);
                    continue;
                }
                const nonce = aead.nonceFor(counter);
                const box = buf[9..n];
                var plain_buf: [envelope.max_encoded_len]u8 = undefined;
                if (aead.open(&plain_buf, box, msg_key, nonce, buf[0..9])) |_| {
                    // успех — только теперь шаг цепочки приёма
                    self.ratchet.commitRecv();
                } else |_| {
                    self.send_mu.unlock(self.io);
                    continue;
                }
                self.send_mu.unlock(self.io);
                const plain_len = box.len - aead.tag_length;
                env = envelope.decode(plain_buf[0..plain_len]) catch continue;
            } else {
                env = envelope.decode(buf[0..n]) catch continue;
            }
            self.ev.onEnvelope(self.ev.ctx, env);
        }
        self.running.store(false, .seq_cst);
        self.ev.onClosed(self.ev.ctx);
    }

    fn fillRandom(self: *Session, dest: []u8) void {
        // counters and nonces come from AEAD/ratchet; only msg_id needs entropy
        self.io.random(dest);
    }
};

test "session: битый sealed-кадр не рассинхронизирует рэтчет" {
    // Зеркальные цепочки: send-цепочка «пира» == recv-цепочка сессии
    const chain_a: [32]u8 = @splat(0x11);
    const chain_b: [32]u8 = @splat(0x22);
    var peer_ratchet = ratchet_mod.Ratchet.init(chain_b, chain_a);

    // валидный sealed-кадр с counter 0 (шифрует «пир»)
    var env_buf: [envelope.max_encoded_len]u8 = undefined;
    const plain = try envelope.encode(&env_buf, .{ .text = .{
        .msg_id = @splat(7),
        .ts_ms = 12345,
        .body = "survivor",
    } });
    var msg_key: [32]u8 = undefined;
    const counter = peer_ratchet.stepSend(&msg_key);
    try std.testing.expectEqual(@as(u64, 0), counter);
    var good: [envelope.max_encoded_len + 64]u8 = undefined;
    good[0] = sealed_tag;
    std.mem.writeInt(u64, good[1..9], counter, .little);
    aead.seal(good[9..], plain, msg_key, aead.nonceFor(counter), good[0..9]);
    const good_frame_len: usize = 9 + plain.len + aead.tag_length;

    // битый sealed-кадр с ТОТ ЖЕ counter 0, но мусор вместо бокса:
    // open обязана провалиться, цепочка приёма сдвигаться НЕ должна
    var bad: [envelope.max_encoded_len + 64]u8 = undefined;
    bad[0] = sealed_tag;
    std.mem.writeInt(u64, bad[1..9], counter, .little);
    const garbage_len: usize = plain.len + aead.tag_length;
    for (bad[9..][0..garbage_len], 0..) |*b, i| b.* = @truncate(i *% 31 +% 5);
    const bad_frame_len: usize = 9 + garbage_len;

    // скрипт провода: [hdr][битый][hdr][валидный]
    var wire: [2 * (envelope.max_encoded_len + 64 + 2)]u8 = undefined;
    var w: usize = 0;
    std.mem.writeInt(u16, wire[w..][0..2], @intCast(bad_frame_len), .little);
    @memcpy(wire[w + 2 ..][0..bad_frame_len], bad[0..bad_frame_len]);
    w += 2 + bad_frame_len;
    std.mem.writeInt(u16, wire[w..][0..2], @intCast(good_frame_len), .little);
    @memcpy(wire[w + 2 ..][0..good_frame_len], good[0..good_frame_len]);
    w += 2 + good_frame_len;

    var script = ScriptConn{ .bytes = wire[0..w] };
    var collector = RxCollector{};
    var s = Session{
        .conn = script.conn(),
        .ratchet = ratchet_mod.Ratchet.init(chain_a, chain_b),
        .keys = .{ .send_key = @splat(0), .recv_key = @splat(0), .transcript = @splat(0) },
        .ev = .{ .ctx = &collector, .onEnvelope = RxCollector.onEnvelope, .onClosed = RxCollector.onClosed },
        .alloc = std.testing.allocator,
        .io = std.testing.io,
    };
    s.rxLoop(); // скрипт исчерпан -> Closed -> выход

    // старый код: stepRecv до open сдвигал цепочку на битом кадре,
    // валидный кадр больше не расшифровывался — сообщение терялось молча
    try std.testing.expect(collector.got);
    try std.testing.expectEqualStrings("survivor", collector.got_body);
    try std.testing.expectEqual(@as(u64, 1), s.ratchet.recv_counter);
}

test "session: повтор sealed-кадра (counter не тот) отбрасывается" {
    const chain_a: [32]u8 = @splat(0x33);
    const chain_b: [32]u8 = @splat(0x44);
    var peer_ratchet = ratchet_mod.Ratchet.init(chain_b, chain_a);

    var env_buf: [envelope.max_encoded_len]u8 = undefined;
    const plain = try envelope.encode(&env_buf, .{ .text = .{
        .msg_id = @splat(9),
        .ts_ms = 1,
        .body = "dup",
    } });
    var msg_key: [32]u8 = undefined;
    const c0 = peer_ratchet.stepSend(&msg_key);
    var box: [envelope.max_encoded_len + 64]u8 = undefined;
    box[0] = sealed_tag;
    std.mem.writeInt(u64, box[1..9], c0, .little);
    aead.seal(box[9..], plain, msg_key, aead.nonceFor(c0), box[0..9]);
    const frame_len: usize = 9 + plain.len + aead.tag_length;

    // один и тот же кадр ДВАЖДЫ: второй — повтор (counter 0 при ожидаемом 1)
    var wire: [2 * (envelope.max_encoded_len + 64 + 2)]u8 = undefined;
    var w: usize = 0;
    for (0..2) |_| {
        std.mem.writeInt(u16, wire[w..][0..2], @intCast(frame_len), .little);
        @memcpy(wire[w + 2 ..][0..frame_len], box[0..frame_len]);
        w += 2 + frame_len;
    }

    var script = ScriptConn{ .bytes = wire[0..w] };
    var collector = RxCollector{};
    var s = Session{
        .conn = script.conn(),
        .ratchet = ratchet_mod.Ratchet.init(chain_a, chain_b),
        .keys = .{ .send_key = @splat(0), .recv_key = @splat(0), .transcript = @splat(0) },
        .ev = .{ .ctx = &collector, .onEnvelope = RxCollector.onEnvelope, .onClosed = RxCollector.onClosed },
        .alloc = std.testing.allocator,
        .io = std.testing.io,
    };
    s.rxLoop();

    // первый принят, повтор отброшен: ровно одно событие, счётчик 1
    try std.testing.expect(collector.got);
    try std.testing.expectEqualStrings("dup", collector.got_body);
    try std.testing.expectEqual(@as(u64, 1), s.ratchet.recv_counter);
}

/// Пишет кадр [len u16 LE][payload] ОДНИМ writeAll: заголовок и payload
/// собираются в `frame` (нужно frame.len >= 2 + payload.len) и уходят в
/// транспорт одним куском — на обф-слое это один кадр и один syscall
/// (заголовок отдельным writeAll стоил бы второй obf-кадр на каждое
/// сообщение: 2 байта раздували до 128 байт на проводе).
fn writeFrame(conn: interfaces.Conn, frame: []u8, payload: []const u8) error{ FrameTooBig, Closed }!void {
    if (payload.len > 65535 or frame.len < 2 + payload.len) return error.FrameTooBig;
    std.mem.writeInt(u16, frame[0..2], @intCast(payload.len), .little);
    @memcpy(frame[2..][0..payload.len], payload);
    conn.writeAll(frame[0 .. 2 + payload.len]) catch return error.Closed;
}

fn readFrame(conn: interfaces.Conn, buf: []u8) !usize {
    var hdr: [2]u8 = undefined;
    try conn.readAll(&hdr);
    const len = std.mem.readInt(u16, &hdr, .little);
    if (len > buf.len) return error.FrameTooBig;
    try conn.readAll(buf[0..len]);
    return len;
}

test "session module compiles" {
    _ = Session;
    _ = SessionError;
}

// ==== Тест rxLoop: битый sealed-кадр не рассинхронизирует рэтчет ====

/// Фейковый Conn: readAll последовательно выдаёт заготовленные байты,
/// исчерпание — Closed. writeAll не нужен (приём только).
const ScriptConn = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn readAllImpl(ptr: *anyopaque, buf: []u8) interfaces.ConnError!void {
        const self: *ScriptConn = @ptrCast(@alignCast(ptr));
        const avail = self.bytes.len - self.pos;
        if (buf.len > avail) return error.Closed;
        @memcpy(buf, self.bytes[self.pos..][0..buf.len]);
        self.pos += buf.len;
    }

    fn writeAllImpl(ptr: *anyopaque, bytes: []const u8) interfaces.ConnError!void {
        _ = ptr;
        _ = bytes;
    }

    fn closeImpl(ptr: *anyopaque) void {
        _ = ptr;
    }

    const vtable = interfaces.Conn.VTable{
        .readAll = readAllImpl,
        .writeAll = writeAllImpl,
        .close = closeImpl,
    };

    fn conn(self: *ScriptConn) interfaces.Conn {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const RxCollector = struct {
    got_body: []const u8 = "",
    got: bool = false,

    fn onEnvelope(ctx: *anyopaque, env: envelope.Envelope) void {
        const self: *RxCollector = @ptrCast(@alignCast(ctx));
        switch (env) {
            .text => |t| {
                self.got = true;
                self.got_body = t.body;
            },
            else => {},
        }
    }

    fn onClosed(ctx: *anyopaque) void {
        _ = ctx;
    }
};
