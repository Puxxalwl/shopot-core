//! One encrypted session with one contact over one transport connection.
//! Flow: transport connect -> XX handshake (both identities authenticated by
//! Ed25519 signatures over the transcript) -> traffic keys -> caller-provided
//! stream wrapper (obfuscated AEAD) -> framed envelopes. TEXT payloads are
//! additionally sealed by the per-message ratchet: two independent crypto
//! layers, each with its own forward secrecy.
//!
//! PCS-ротация рэтчета: каждые rotate_every отправленных сообщений сторона
//! генерирует свежую X25519-пару и шлёт паблик конвертом RATCHET_KEY; когда
//! у обеих сторон есть оба fresh-паблика, обе делают dhStep — цепочки
//! пересоздаются, эпоха +1. Sealed-кадры несут эпоху: кадры предыдущей
//! эпохи «в полёте» расшифровываются по снапшоту цепочки (prev_recv),
//! снапшот гасится первым кадром новой эпохи (порядок потока гарантирует,
//! что старых кадров больше не будет).
const std = @import("std");
const interfaces = @import("interfaces.zig");
const handshake = @import("../crypto/handshake.zig");
const ratchet_mod = @import("../crypto/ratchet.zig");
const kdf = @import("../crypto/kdf.zig");
const aead = @import("../crypto/aead.zig");
const identity_mod = @import("../crypto/identity.zig");
const envelope = @import("../proto/envelope.zig");

const X25519 = std.crypto.dh.X25519;
const flate = std.compress.flate;

/// Порог сжатия payload sealed-кадра: ниже не отбить zlib-оверхед
/// (~6 байт хедер+чексумма) на кадре с 26 байтами AEAD/обф-оверхеда.
const compress_min_len: usize = 512;
/// Сжатие обязано выиграть хотя бы столько, чтобы кадр не вырос.
const compress_min_gain: usize = 64;

/// zlib-сжатие payload sealed-кадра. Возвращает длину сжатых данных в
/// out_buf либо null (нечего жать / уже сжатое / не выиграли). Детерминизм
/// не требуется — данные под AEAD, важна только обратимость.
fn compressPayload(plain: []const u8, out_buf: []u8) ?usize {
    if (plain.len < compress_min_len) return null;
    if (looksCompressed(plain)) return null;
    var w: std.Io.Writer = .fixed(out_buf);
    // окно 64 КБ — стек отправителя; level_6 (zlib default)
    var window: [flate.max_window_len]u8 = undefined;
    var c = flate.Compress.init(&w, &window, .zlib, .default) catch return null;
    c.writer.writeAll(plain) catch return null;
    c.finish() catch return null;
    const n = w.buffered().len;
    if (n + compress_min_gain >= plain.len) return null;
    return n;
}

/// Разжать zlib payload в out_buf. null — битый поток или декомпрессия
/// больше буфера (zip-бомба: отправитель гарантирует исходный размер
/// ≤ max_encoded_len, больше — атака/порча, кадр отбрасывается).
fn decompressPayload(comp: []const u8, out_buf: []u8) ?usize {
    var r: std.Io.Reader = .fixed(comp);
    var window: [flate.max_window_len]u8 = undefined;
    var d = flate.Decompress.init(&r, .zlib, &window);
    const n = d.reader.readSliceShort(out_buf) catch return null;
    if (n == out_buf.len) {
        // буфер заполнен полностью: данных за ним быть не должно
        var probe: [1]u8 = undefined;
        const extra = d.reader.readSliceShort(&probe) catch return null;
        if (extra != 0) return null;
    }
    if (n == 0) return null;
    return n;
}

/// Payload уже в несжимаемом формате (PNG/JPEG/GZIP/ZIP/ZSTD) — двойное
/// сжатие только раздует кадр. TEXT-тела сюда не попадают, guard на вырост.
fn looksCompressed(p: []const u8) bool {
    if (p.len >= 4) {
        const magic4 = p[0..4];
        if (std.mem.eql(u8, magic4, "\x89PNG")) return true; // PNG
        if (std.mem.eql(u8, magic4, "\x28\xB5\x2F\xFD")) return true; // zstd
        if (std.mem.eql(u8, magic4, "PK\x03\x04")) return true; // zip
    }
    if (p.len >= 3) {
        if (std.mem.eql(u8, p[0..3], "\xFF\xD8\xFF")) return true; // jpeg
    }
    if (p.len >= 2) {
        if (std.mem.eql(u8, p[0..2], "\x1F\x8B")) return true; // gzip
    }
    return false;
}

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
/// Заголовок sealed-кадра: [tag 0xA1][epoch u16 LE][counter u64 LE].
const sealed_hdr_len: usize = 1 + 2 + 8 + 1;

/// Свежая X25519-пара стороны для СЛЕДУЮЩЕЙ эпохи ротации.
const RotPair = struct {
    secret: [32]u8,
    pub_key: [32]u8,
};

/// Снапшот приёмной цепочки предыдущей эпохи: кадры пира, отправленные до
/// его dhStep, приходят после нашего — расшифровываются по снапшоту.
const PrevChain = struct {
    epoch: u16,
    chain: [32]u8,
    counter: u64,
};

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
    /// Порог отправленных сообщений для запуска DH-ротации (PCS).
    /// Тесты уменьшают; 0 — ротация отключена.
    rotate_every: u64 = 256,
    /// Свежая X25519-пара для следующей эпохи (паблик уже отправлен пиру).
    rot_own: ?RotPair = null,
    /// Fresh-паблик пира для следующей эпохи.
    rot_peer: ?[32]u8 = null,
    /// Снапшот приёмной цепочки предыдущей эпохи (кадры пира в полёте).
    prev_recv: ?PrevChain = null,

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
    /// Sealed-кадр: [len u16][tag 0xA1][epoch u16][counter u64][box];
    /// при достижении rotate_every отправок в пачку подмешивается конверт
    /// RATCHET_KEY (запуск PCS-ротации).
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
            // триггер PCS-ротации: порог отправки достигнут, пары ещё нет
            if (self.rotate_every != 0 and self.rot_own == null and
                self.ratchet.send_counter >= self.rotate_every)
            {
                try self.rotateStartLocked(&batch, &used);
            }
            var enc: [envelope.max_encoded_len]u8 = undefined;
            const plain = envelope.encode(&enc, env) catch return SessionError.TooBig;
            // zlib-сжатие длинного payload ДО запечатывания (ROADMAP P1):
            // текст 2-4x, уже-сжатое и невыигрышное — без сжатия
            var comp_buf: [envelope.max_encoded_len]u8 = undefined;
            const payload: []const u8 = if (compressPayload(plain, &comp_buf)) |n|
                comp_buf[0..n]
            else
                plain;
            const compressed = payload.len != plain.len;
            const frame_len: usize = sealed_hdr_len + payload.len + aead.tag_length;
            if (2 + frame_len > batch.len) return SessionError.TooBig;
            if (used > 0 and used + 2 + frame_len > batch.len) {
                // следующий кадр не влезает: флеш накопленного
                self.conn.writeAll(batch[0..used]) catch return SessionError.Closed;
                used = 0;
            }
            // ratchet-запечатывание прямо в batch (2 байта заголовка кадра
            // спереди): один conn.writeAll на всю пачку
            var msg_key: [32]u8 = undefined;
            const counter = self.ratchet.stepSend(&msg_key);
            const dst = batch[used..];
            dst[2] = sealed_tag;
            std.mem.writeInt(u16, dst[3..5], self.ratchet.epoch, .little);
            std.mem.writeInt(u64, dst[5..13], counter, .little);
            // флаг сжатия в sealed-заголовке: покрывается AD — подделать
            // флаг без ключа нельзя, разжатие идёт после AEAD-open
            dst[13] = @intFromBool(compressed);
            const nonce = aead.nonceFor(counter);
            aead.seal(dst[14..], payload, msg_key, nonce, dst[2 .. 2 + sealed_hdr_len]);
            std.mem.writeInt(u16, dst[0..2], @intCast(frame_len), .little);
            used += 2 + frame_len;
        }
        if (used > 0) self.conn.writeAll(batch[0..used]) catch return SessionError.Closed;
    }

    /// Генерирует свежую X25519-пару и отправляет паблик пиру конвертом
    /// RATCHET_KEY (в пачку, если она идёт, иначе отдельным writeAll).
    /// Только под send_mu. Ошибка записи — ротация не стартует.
    fn rotateStartLocked(self: *Session, batch: ?[]u8, used: *usize) SessionError!void {
        const kp = X25519.KeyPair.generate(self.io);
        var f: [2 + 35]u8 = undefined;
        const plain = envelope.encode(f[2..], .{ .ratchet_key = .{
            .epoch = self.ratchet.epoch +% 1,
            .dh_pub = kp.public_key,
        } }) catch return SessionError.TooBig;
        std.mem.writeInt(u16, f[0..2], @intCast(plain.len), .little);
        const frame = f[0 .. 2 + plain.len];
        if (batch) |b| {
            // флешим пачку, если конверт не влезает (порядок потока важен)
            if (used.* > 0 and used.* + frame.len > b.len) {
                self.conn.writeAll(b[0..used.*]) catch return SessionError.Closed;
                used.* = 0;
            }
            @memcpy(b[used.*..][0..frame.len], frame);
            used.* += frame.len;
        } else {
            self.conn.writeAll(frame) catch return SessionError.Closed;
        }
        self.rot_own = .{ .secret = kp.secret_key, .pub_key = kp.public_key };
    }

    /// Пир прислал fresh-паблик (конверт RATCHET_KEY). Только следующая
    /// эпоха; дубликаты и отставание игнорируются. Если своей пары ещё нет —
    /// генерируем и отвечаем, затем (обе части есть) — совместный dhStep.
    /// Вызывается из rx-потока под send_mu.
    fn handleRatchetKeyLocked(self: *Session, m: envelope.RatchetKey) void {
        if (self.rotate_every == 0) return; // ротация отключена
        if (m.epoch != self.ratchet.epoch +% 1) return;
        if (self.rot_peer != null) return;
        self.rot_peer = m.dh_pub;
        if (self.rot_own == null) {
            var unused: usize = 0;
            self.rotateStartLocked(null, &unused) catch return;
        }
        self.tryAdvanceLocked();
    }

    /// Совместный DH-шаг: обе части есть → снапшот приёмной цепочки (кадры
    /// пира в полёте), dhStep, секреты стёрты. Вырожденный DH-паблик пира —
    /// враждебный протокол-нарушитель: сессия закрывается (peer-side уже
    /// ротировался, цепочки всё равно разойдутся).
    fn tryAdvanceLocked(self: *Session) void {
        if (self.rot_own == null or self.rot_peer == null) return;
        const peer = self.rot_peer.?;
        var own_secret = self.rot_own.?.secret;
        self.prev_recv = .{
            .epoch = self.ratchet.epoch,
            .chain = self.ratchet.chain_recv,
            .counter = self.ratchet.recv_counter,
        };
        self.ratchet.dhStep(peer, own_secret) catch {
            // низкопорядковый паблик: peer не мог честно ротироваться с ним
            self.prev_recv = null;
            self.closeConn();
            return;
        };
        std.crypto.secureZero(u8, &own_secret);
        std.crypto.secureZero(u8, &self.rot_own.?.secret);
        self.rot_own = null;
        self.rot_peer = null;
    }

    /// Закрыть транспорт (без join rx-потока — мы может быть В нём).
    fn closeConn(self: *Session) void {
        if (self.running.swap(false, .seq_cst)) {
            self.conn.close();
        }
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
        // plain-буфер живёт в кадре rxLoop: срезы конвертов (body) из него
        // валидны до конца итерации, пока onEnvelope их не разберёт
        var plain_buf: [envelope.max_encoded_len]u8 = undefined;
        while (self.running.load(.seq_cst)) {
            const n = readFrame(self.conn, &buf) catch break;
            if (n == 0) break;
            var env: envelope.Envelope = undefined;
            if (buf[0] == sealed_tag) {
                env = self.rxSealed(buf[0..n], &plain_buf) orelse continue;
            } else {
                env = envelope.decode(buf[0..n]) catch continue;
            }
            // RATCHET_KEY — протокол ротации, сессия съедает его сама:
            // движок крипто-состояние сессии не видит
            if (env == .ratchet_key) {
                self.send_mu.lockUncancelable(self.io);
                defer self.send_mu.unlock(self.io);
                self.handleRatchetKeyLocked(env.ratchet_key);
                continue;
            }
            self.ev.onEnvelope(self.ev.ctx, env);
        }
        self.running.store(false, .seq_cst);
        self.ev.onClosed(self.ev.ctx);
    }

    /// Расшифровка sealed-кадра [tag][epoch u16][counter u64][box] под
    /// send_mu. Текущая эпоха: peekRecv (ключ без сдвига цепочки, счётчик
    /// обязан совпасть — повтор/перестановка отбрасываются), commitRecv
    /// только после успешного open (Double Ratchet spec §3.5: один битый
    /// кадр не рассинхронизирует стороны). Предыдущая эпоха: кадры пира
    /// «в полёте» (отправлены до его dhStep, пришли после нашего) — ключ из
    /// снапшота prev_recv, счётчик строго продолжает последовательность.
    /// Первый успешный кадр текущей (новой) эпохи гасит снапшот: порядок
    /// потока гарантирует, что старых кадров пира больше не будет.
    /// null — кадр отброшен (битый/чужая эпоха/повтор счётчика).
    /// Открытый текст кладётся в `plain_buf` КАДРА ВЫЗЫВАЮЩЕГО: срезы
    /// декодированного конверта обязаны жить после возврата.
    fn rxSealed(self: *Session, frame: []const u8, plain_buf: []u8) ?envelope.Envelope {
        if (frame.len < sealed_hdr_len + aead.tag_length) return null;
        const epoch = std.mem.readInt(u16, frame[1..3], .little);
        const counter = std.mem.readInt(u64, frame[3..11], .little);
        const compressed = frame[11] != 0;
        const box = frame[sealed_hdr_len..];
        const ad = frame[0..sealed_hdr_len];

        self.send_mu.lockUncancelable(self.io);
        defer self.send_mu.unlock(self.io);

        var msg_key: [32]u8 = undefined;
        var commit_current = false;
        var commit_prev = false;

        if (epoch == self.ratchet.epoch) {
            const expected = self.ratchet.peekRecv(&msg_key);
            if (counter != expected) return null;
            if (aead.open(plain_buf, box, msg_key, aead.nonceFor(counter), ad)) |_| {
                commit_current = true;
            } else |_| {
                return null;
            }
        } else if (self.prev_recv != null and epoch == self.prev_recv.?.epoch) {
            const p: *PrevChain = &self.prev_recv.?;
            if (counter != p.counter) return null;
            ratchet_mod.Ratchet.deriveKey(p.chain, counter, &msg_key);
            if (aead.open(plain_buf, box, msg_key, aead.nonceFor(counter), ad)) |_| {
                commit_prev = true;
            } else |_| {
                return null;
            }
        } else {
            // неизвестная/слишком старая эпоха — кадр отбрасывается
            return null;
        }

        // сжатый payload: разжать ПОСЛЕ AEAD-open (флаг в AD аутентичен),
        // разжатое обязано влезть в plain_buf — иначе бомба/порча
        var plain_len = box.len - aead.tag_length;
        if (compressed) {
            var comp_scratch: [envelope.max_encoded_len]u8 = undefined;
            @memcpy(comp_scratch[0..plain_len], plain_buf[0..plain_len]);
            plain_len = decompressPayload(comp_scratch[0..plain_len], plain_buf) orelse
                return null;
        }
        const env = envelope.decode(plain_buf[0..plain_len]) catch return null;
        if (commit_current) {
            self.ratchet.commitRecv();
            // кадр НОВОЙ эпохи дошёл — старых кадров пира больше не будет
            if (self.prev_recv != null) {
                std.crypto.secureZero(u8, &self.prev_recv.?.chain);
                self.prev_recv = null;
            }
        }
        if (commit_prev) {
            const p: *PrevChain = &self.prev_recv.?;
            ratchet_mod.Ratchet.stepChainForward(&p.chain);
            p.counter += 1;
        }
        return env;
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
    std.mem.writeInt(u16, good[1..3], peer_ratchet.epoch, .little);
    std.mem.writeInt(u64, good[3..11], counter, .little);
    good[11] = 0; // без сжатия
    aead.seal(good[12..], plain, msg_key, aead.nonceFor(counter), good[0..sealed_hdr_len]);
    const good_frame_len: usize = sealed_hdr_len + plain.len + aead.tag_length;

    // битый sealed-кадр с ТОТ ЖЕ counter 0, но мусор вместо бокса:
    // open обязана провалиться, цепочка приёма сдвигаться НЕ должна
    var bad: [envelope.max_encoded_len + 64]u8 = undefined;
    bad[0] = sealed_tag;
    std.mem.writeInt(u16, bad[1..3], peer_ratchet.epoch, .little);
    std.mem.writeInt(u64, bad[3..11], counter, .little);
    bad[11] = 0; // без сжатия
    const garbage_len: usize = plain.len + aead.tag_length;
    for (bad[12..][0..garbage_len], 0..) |*b, i| b.* = @truncate(i *% 31 +% 5);
    const bad_frame_len: usize = sealed_hdr_len + garbage_len;

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
    try std.testing.expectEqualStrings("survivor", collector.bodyOf(0));
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
    std.mem.writeInt(u16, box[1..3], peer_ratchet.epoch, .little);
    std.mem.writeInt(u64, box[3..11], c0, .little);
    box[11] = 0; // без сжатия
    aead.seal(box[12..], plain, msg_key, aead.nonceFor(c0), box[0..sealed_hdr_len]);
    const frame_len: usize = sealed_hdr_len + plain.len + aead.tag_length;

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
    try std.testing.expectEqualStrings("dup", collector.bodyOf(0));
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

test "session: zlib-сжатие payload — roundtrip, порог, несжимаемое" {
    // длинный текст ~3.5 КБ (порог 512 пройден, отдача 2x+)
    var plain: [3500]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    prng.random().bytes(&plain);
    // русский текст в UTF-8: многобайтовые кодпоинты — реальный кейс TEXT
    const word = "привет, ";
    for (&plain, 0..) |*b, i| b.* = word[i % word.len];
    var out: [envelope.max_encoded_len]u8 = undefined;
    const n = compressPayload(&plain, &out) orelse return error.TestUnexpectedResult;
    try std.testing.expect(n < plain.len / 2); // текст обязан жаться 2x+
    // roundtrip
    var back: [envelope.max_encoded_len]u8 = undefined;
    const m = decompressPayload(out[0..n], &back) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(plain.len, m);
    try std.testing.expectEqualSlices(u8, &plain, back[0..m]);

    // ниже порога — не жмём
    var small: [64]u8 = undefined;
    @memset(&small, 'a');
    try std.testing.expect(compressPayload(&small, &out) == null);

    // уже-сжатое (PNG-магия) — не жмём
    var png: [2048]u8 = undefined;
    @memset(&png, 0xAB);
    png[0..4].* = .{ 0x89, 'P', 'N', 'G' };
    try std.testing.expect(compressPayload(&png, &out) == null);

    // высокоэнтропийный мусор: может и не выиграть — тогда null (не ошибка)
    var rnd: [4096]u8 = undefined;
    prng.random().bytes(&rnd);
    if (compressPayload(&rnd, &out)) |rn| {
        // если уж сжали — обязана быть честная обратимость
        const rm = decompressPayload(out[0..rn], &back) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualSlices(u8, &rnd, back[0..rm]);
    }

    // бомба: маленький сжатый кусок, разжимающийся больше буфера — null
    var big: [envelope.max_encoded_len]u8 = undefined;
    @memset(&big, 0x00);
    var bomb_comp: [envelope.max_encoded_len + 128]u8 = undefined;
    const bn = compressPayload(&big, &bomb_comp) orelse return error.TestUnexpectedResult;
    try std.testing.expect(bn < big.len / 8);
    // буфер вдвое меньше — не влезает, обязаны отказаться
    var small_out: [envelope.max_encoded_len / 2]u8 = undefined;
    try std.testing.expect(decompressPayload(bomb_comp[0..bn], &small_out) == null);

    // битый zlib-поток — null
    try std.testing.expect(decompressPayload(out[0..8], &back) == null);
}

test "session module compiles" {
    _ = Session;
    _ = SessionError;
}

// ==== Тест rxLoop: битый sealed-кадр не рассинхронизирует рэтчет ====

/// Фейковый Conn: readAll последовательно выдаёт заготовленные байты,
/// исчерпание — Closed. writeAll захватывает записанное в `out` (сессия
/// так отвечает конвертом RATCHET_KEY — тест парсит паблик из ответа).
const ScriptConn = struct {
    bytes: []const u8,
    pos: usize = 0,
    out: [128]u8 = undefined,
    out_len: usize = 0,

    fn readAllImpl(ptr: *anyopaque, buf: []u8) interfaces.ConnError!void {
        const self: *ScriptConn = @ptrCast(@alignCast(ptr));
        const avail = self.bytes.len - self.pos;
        if (buf.len > avail) return error.Closed;
        @memcpy(buf, self.bytes[self.pos..][0..buf.len]);
        self.pos += buf.len;
    }

    fn writeAllImpl(ptr: *anyopaque, bytes: []const u8) interfaces.ConnError!void {
        const self: *ScriptConn = @ptrCast(@alignCast(ptr));
        if (bytes.len > self.out.len - self.out_len) return error.Closed;
        @memcpy(self.out[self.out_len..][0..bytes.len], bytes);
        self.out_len += bytes.len;
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

/// Сборщик TEXT-событий: тела КОПИРУЮТСЯ в фиксированные буферы — срезы
/// onEnvelope указывают в стек rxSealed и вне вызова невалидны.
const RxCollector = struct {
    got: bool = false,
    count: u32 = 0,
    bodies: [8][16]u8 = @splat(@splat(0)),
    lens: [8]u8 = @splat(0),

    fn onEnvelope(ctx: *anyopaque, env: envelope.Envelope) void {
        const self: *RxCollector = @ptrCast(@alignCast(ctx));
        switch (env) {
            .text => |t| {
                self.got = true;
                if (self.count < self.bodies.len) {
                    const n: u8 = @intCast(@min(t.body.len, 16));
                    @memcpy(self.bodies[self.count][0..n], t.body[0..n]);
                    self.lens[self.count] = n;
                }
                self.count += 1;
            },
            else => {},
        }
    }

    fn onClosed(ctx: *anyopaque) void {
        _ = ctx;
    }

    /// Тело i-го принятого TEXT (копия, ≤ 16 байтов).
    fn bodyOf(self: *const RxCollector, i: usize) []const u8 {
        return self.bodies[i][0..self.lens[i]];
    }
};

/// Тестовый хелпер: sealed-кадр [tag][epoch u16][counter u64][box] с шагом
/// рэтчета отправителя `r`; возвращает длину кадра, пишет в `out`.
fn sealFrame(out: []u8, r: *ratchet_mod.Ratchet, body: []const u8) usize {
    var env_buf: [envelope.max_encoded_len]u8 = undefined;
    const plain = envelope.encode(&env_buf, .{ .text = .{
        .msg_id = @splat(7),
        .ts_ms = 1,
        .body = body,
    } }) catch unreachable;
    var msg_key: [32]u8 = undefined;
    const counter = r.stepSend(&msg_key);
    out[0] = sealed_tag;
    std.mem.writeInt(u16, out[1..3], r.epoch, .little);
    std.mem.writeInt(u64, out[3..11], counter, .little);
    out[11] = 0; // без сжатия
    aead.seal(out[12..], plain, msg_key, aead.nonceFor(counter), out[0..sealed_hdr_len]);
    return sealed_hdr_len + plain.len + aead.tag_length;
}

/// Тестовый хелпер: кадр [len u16][payload] в конец `wire` (w — позиция).
fn pushFrame(wire: []u8, w: *usize, payload: []const u8) void {
    std.mem.writeInt(u16, wire[w.*..][0..2], @intCast(payload.len), .little);
    @memcpy(wire[w.* + 2 ..][0..payload.len], payload);
    w.* += 2 + payload.len;
}

test "session: PCS-ротация — dhStep, кадры в полёте, новая эпоха" {
    const chain_a: [32]u8 = @splat(0x51);
    const chain_b: [32]u8 = @splat(0x62);
    // сессия s: send=chain_a, recv=chain_b; пир зеркально
    var peer = ratchet_mod.Ratchet.init(chain_b, chain_a);

    // фаза 1: 2 sealed-кадра эпохи 0, конверт RATCHET_KEY пира, ещё один
    // кадр эпохи 0 «в полёте» (пир отослал его до своего dhStep)
    const peer_kp = X25519.KeyPair.generate(std.testing.io);
    var wire1: [512]u8 = undefined;
    var w: usize = 0;
    {
        var f: [envelope.max_encoded_len + 64]u8 = undefined;
        pushFrame(&wire1, &w, f[0..sealFrame(&f, &peer, "msg-0")]);
        pushFrame(&wire1, &w, f[0..sealFrame(&f, &peer, "msg-1")]);
    }
    {
        // RATCHET_KEY пира для эпохи 1
        var env_buf: [envelope.max_encoded_len]u8 = undefined;
        const rk = try envelope.encode(&env_buf, .{ .ratchet_key = .{
            .epoch = 1,
            .dh_pub = peer_kp.public_key,
        } });
        pushFrame(&wire1, &w, rk);
    }
    {
        var f: [envelope.max_encoded_len + 64]u8 = undefined;
        pushFrame(&wire1, &w, f[0..sealFrame(&f, &peer, "flight")]);
    }

    var script = ScriptConn{ .bytes = wire1[0..w] };
    var collector = RxCollector{};
    var s = Session{
        .conn = script.conn(),
        .ratchet = ratchet_mod.Ratchet.init(chain_a, chain_b),
        .keys = .{ .send_key = @splat(0), .recv_key = @splat(0), .transcript = @splat(0) },
        .ev = .{ .ctx = &collector, .onEnvelope = RxCollector.onEnvelope, .onClosed = RxCollector.onClosed },
        .alloc = std.testing.allocator,
        .io = std.testing.io,
        .rotate_every = 4,
    };
    s.rxLoop(); // RATCHET_KEY: s отвечает пабликом и делает dhStep

    // сессия ротировалась: эпоха 1, s дёрнула счётчики приёма в 0
    try std.testing.expectEqual(@as(u16, 1), s.ratchet.epoch);
    try std.testing.expect(s.rot_own == null);
    try std.testing.expect(s.rot_peer == null);
    // кадр «в полёте» (эпоха 0, counter 2) расшифрован по снапшоту
    try std.testing.expectEqual(@as(u32, 3), collector.count);
    try std.testing.expectEqualStrings("msg-0", collector.bodyOf(0));
    try std.testing.expectEqualStrings("flight", collector.bodyOf(2));
    // снапшот ещё жив: новых кадров эпохи 1 не было
    try std.testing.expect(s.prev_recv != null);
    try std.testing.expectEqual(@as(u16, 0), s.prev_recv.?.epoch);
    try std.testing.expectEqual(@as(u64, 3), s.prev_recv.?.counter);

    // ответ сессии — конверт RATCHET_KEY: парсим паблик, пир делает dhStep
    try std.testing.expectEqual(@as(usize, 2 + 1 + 2 + 32), script.out_len);
    try std.testing.expectEqual(envelope.Tag.ratchet_key, @as(envelope.Tag, @fromBackingInt(@intCast(script.out[2]))));
    const s_pub = script.out[5..37].*;
    try peer.dhStep(s_pub, peer_kp.secret_key);
    try std.testing.expectEqual(@as(u16, 1), peer.epoch);

    // фаза 2: кадры НОВОЙ эпохи; первый кадр эпохи 1 гасит снапшот
    var wire2: [512]u8 = undefined;
    w = 0;
    {
        var f: [envelope.max_encoded_len + 64]u8 = undefined;
        pushFrame(&wire2, &w, f[0..sealFrame(&f, &peer, "new-0")]);
        pushFrame(&wire2, &w, f[0..sealFrame(&f, &peer, "new-1")]);
    }
    var script2 = ScriptConn{ .bytes = wire2[0..w] };
    s.conn = script2.conn();
    s.running.store(true, .seq_cst);
    s.rxLoop();

    try std.testing.expectEqual(@as(u32, 5), collector.count);
    try std.testing.expectEqualStrings("new-0", collector.bodyOf(3));
    try std.testing.expectEqualStrings("new-1", collector.bodyOf(4));
    // первый кадр новой эпохи погасил снапшот: старых кадров не будет
    try std.testing.expect(s.prev_recv == null);
    try std.testing.expectEqual(@as(u64, 2), s.ratchet.recv_counter);
}
