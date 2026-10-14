//! envelope — бинарные конверты протокола v3 (без JSON).
//!
//! Кадр: тег (u8), затем поля little-endian (см. codec.zig). Поля переменной
//! длины (тело TEXT, аудио CALL_AUDIO) имеют префикс длины u16. Декодер
//! возвращает union с типизированными полями; аллокаций нет — срезы `body`/
//! `data` указывают во входной буфер.
//!
//! Раскладка кадров:
//!   TEXT          0x10: msg_id: [16]u8, ts_ms: u64, body: u16 + байты (≤ 4096)
//!   REACT         0x13: msg_id: [16]u8, op: u8, code: u8
//!   BLOCK_NOTICE  0x14: reason: u8
//!   PRESENCE_PING 0x20: seq: u32, ts_ms: u64
//!   PRESENCE_PONG 0x21: seq: u32, ts_peer_ms: u64
//!   CALL_SIGNAL   0x30: op: u8, call_id: [16]u8
//!   CALL_AUDIO    0x31: seq: u32, data: u16 + байты (≤ 1024)
//!   JOIN          0x40: bundle: [64]u8, name: u8 + байты (≤ 32),
//!                       sig: [64]u8, hmac: [32]u8

const std = @import("std");
const codec = @import("codec.zig");

/// Теги кадров протокола v3.
pub const Tag = enum(u8) {
    /// Текстовое сообщение.
    text = 0x10,
    /// Реакция на сообщение.
    react = 0x13,
    /// Уведомление о блокировке.
    block_notice = 0x14,
    /// Пинг присутствия.
    presence_ping = 0x20,
    /// Ответ на пинг присутствия.
    presence_pong = 0x21,
    /// Сигнальное сообщение звонка.
    call_signal = 0x30,
    /// Аудиокадр звонка.
    call_audio = 0x31,
    /// JOIN: предъявление одностороннего инвайта (HMAC по секрету кода).
    join = 0x40,
};

/// Максимум длины имени в JOIN.
pub const max_join_name = 32;
/// Длина Ed25519-подписи в JOIN.
pub const join_sig_len = 64;
/// Длина HMAC-SHA256 в JOIN.
pub const join_hmac_len = 32;

/// REACT.op: добавить реакцию.
pub const react_add: u8 = 1;
/// REACT.op: снять реакцию.
pub const react_remove: u8 = 2;

/// CALL_SIGNAL.op: предложение звонка.
pub const call_offer: u8 = 0;
/// CALL_SIGNAL.op: принятие звонка.
pub const call_accept: u8 = 1;
/// CALL_SIGNAL.op: отклонение звонка.
pub const call_reject: u8 = 2;
/// CALL_SIGNAL.op: завершение звонка.
pub const call_end: u8 = 3;

/// Длина идентификаторов (msg_id, call_id).
pub const id_len = 16;
/// Максимум длины тела TEXT.
pub const max_text_body = 4096;
/// Максимум длины DATA в CALL_AUDIO.
pub const max_audio_data = 1024;

/// Максимальная длина закодированного кадра (TEXT с телом 4096).
pub const max_encoded_len = 1 + id_len + 8 + 2 + max_text_body;

/// TEXT (0x10): текстовое сообщение.
pub const Text = struct {
    /// Идентификатор сообщения.
    msg_id: [id_len]u8,
    /// Метка времени отправителя, мс.
    ts_ms: u64,
    /// Тело сообщения, ≤ 4096 байтов; срез входного буфера после decode.
    body: []const u8,
};

/// REACT (0x13): реакция на сообщение.
pub const React = struct {
    /// Идентификатор сообщения.
    msg_id: [id_len]u8,
    /// 1 = добавить, 2 = снять (см. react_add/react_remove).
    op: u8,
    /// Код реакции.
    code: u8,
};

/// BLOCK_NOTICE (0x14): уведомление о блокировке.
pub const BlockNotice = struct {
    /// Код причины блокировки.
    reason: u8,
};

/// PRESENCE_PING (0x20): пинг присутствия.
pub const PresencePing = struct {
    /// Порядковый номер пинга.
    seq: u32,
    /// Метка времени отправителя, мс.
    ts_ms: u64,
};

/// PRESENCE_PONG (0x21): ответ на пинг присутствия.
pub const PresencePong = struct {
    /// Порядковый номер из пинга.
    seq: u32,
    /// Метка времени пира, мс.
    ts_peer_ms: u64,
};

/// CALL_SIGNAL (0x30): сигнальное сообщение звонка.
pub const CallSignal = struct {
    /// 0 = offer, 1 = accept, 2 = reject, 3 = end (см. call_* константы).
    op: u8,
    /// Идентификатор звонка.
    call_id: [id_len]u8,
};

/// CALL_AUDIO (0x31): аудиокадр звонка.
pub const CallAudio = struct {
    /// Порядковый номер кадра.
    seq: u32,
    /// Полезная нагрузка, ≤ 1024 байтов; срез входного буфера после decode.
    data: []const u8,
};

/// JOIN (0x40): держатель инвайт-кода доказывает право на подключение.
/// Отправляется первым конвертом сразу после рукопожатия.
pub const Join = struct {
    /// Полный bundle подключающегося: enc_pk || sign_pk.
    bundle: [64]u8,
    /// Имя подключающегося, ≤ 32 байтов; срез входного буфера после decode.
    name: []const u8,
    /// Ed25519-подпись подписавшего над transcript рукопожатия —
    /// связывает bundle с ключами сессии (анти-MITM).
    sig: [join_sig_len]u8,
    /// HMAC-SHA256(invite_secret, transcript) — доказательство держателя
    /// кода; сверяется по реестру секретов приглашающего.
    hmac: [join_hmac_len]u8,
};

/// Конверт протокола v3: один из семи кадров.
pub const Envelope = union(enum) {
    /// TEXT (0x10).
    text: Text,
    /// REACT (0x13).
    react: React,
    /// BLOCK_NOTICE (0x14).
    block_notice: BlockNotice,
    /// PRESENCE_PING (0x20).
    presence_ping: PresencePing,
    /// PRESENCE_PONG (0x21).
    presence_pong: PresencePong,
    /// CALL_SIGNAL (0x30).
    call_signal: CallSignal,
    /// CALL_AUDIO (0x31).
    call_audio: CallAudio,
    /// JOIN (0x40).
    join: Join,
};

/// Ошибки кодирования: мал буфер или payload превышает максимум протокола.
pub const EncodeError = codec.Writer.Error || error{TooBig};

/// Точная длина закодированного кадра `e` в байтах — для подбора буфера.
pub fn encodedLen(e: Envelope) usize {
    return switch (e) {
        .text => |m| 1 + id_len + 8 + 2 + m.body.len,
        .react, .call_signal => 1 + id_len + 1,
        .block_notice => 2,
        .presence_ping, .presence_pong => 1 + 4 + 8,
        .call_audio => |m| 1 + 4 + 2 + m.data.len,
        .join => |m| 1 + 64 + 1 + m.name.len + join_sig_len + join_hmac_len,
    };
}

/// Кодирует `e` в `buf` и возвращает использованный срез `buf`.
/// Ошибки: NoSpace — буфер короче encodedLen(e); TooBig — тело TEXT > 4096
/// или DATA в CALL_AUDIO > 1024. Аллокаций нет.
pub fn encode(buf: []u8, e: Envelope) EncodeError![]const u8 {
    var w = codec.Writer.init(buf);
    switch (e) {
        .text => |m| {
            if (m.body.len > max_text_body) return error.TooBig;
            try w.put(@backingInt(Tag.text));
            try w.putFixed(&m.msg_id);
            try w.putInt(u64, m.ts_ms);
            try w.putBytes(m.body);
        },
        .react => |m| {
            try w.put(@backingInt(Tag.react));
            try w.putFixed(&m.msg_id);
            try w.put(m.op);
            try w.put(m.code);
        },
        .block_notice => |m| {
            try w.put(@backingInt(Tag.block_notice));
            try w.put(m.reason);
        },
        .presence_ping => |m| {
            try w.put(@backingInt(Tag.presence_ping));
            try w.putInt(u32, m.seq);
            try w.putInt(u64, m.ts_ms);
        },
        .presence_pong => |m| {
            try w.put(@backingInt(Tag.presence_pong));
            try w.putInt(u32, m.seq);
            try w.putInt(u64, m.ts_peer_ms);
        },
        .call_signal => |m| {
            try w.put(@backingInt(Tag.call_signal));
            try w.put(m.op);
            try w.putFixed(&m.call_id);
        },
        .call_audio => |m| {
            if (m.data.len > max_audio_data) return error.TooBig;
            try w.put(@backingInt(Tag.call_audio));
            try w.putInt(u32, m.seq);
            try w.putBytes(m.data);
        },
        .join => |m| {
            if (m.name.len > max_join_name) return error.TooBig;
            try w.put(@backingInt(Tag.join));
            try w.putFixed(&m.bundle);
            try w.put(@intCast(m.name.len));
            try w.putFixed(m.name);
            try w.putFixed(&m.sig);
            try w.putFixed(&m.hmac);
        },
    }
    return w.buf[0..w.pos];
}

/// Ошибки декодирования: кадр обрезан, тег неизвестен, есть лишний хвост
/// либо заявленная длина превышает максимум протокола.
pub const DecodeError = error{ Truncated, UnknownTag, BadLen };

/// Декодирует ровно один кадр из `bytes`. Срезы `body`/`data` указывают
/// в `bytes` (без копий). Хвост после кадра или превышение максимумов
/// протокола — BadLen. Аллокаций нет.
pub fn decode(bytes: []const u8) DecodeError!Envelope {
    var r = codec.Reader.init(bytes);
    const tag_byte = try r.getU8();

    const e: Envelope = switch (tag_byte) {
        @backingInt(Tag.text) => .{ .text = .{
            .msg_id = try readId(&r),
            .ts_ms = try r.getInt(u64),
            .body = blk: {
                const body = try r.getBytes();
                if (body.len > max_text_body) return error.BadLen;
                break :blk body;
            },
        } },
        @backingInt(Tag.react) => .{ .react = .{
            .msg_id = try readId(&r),
            .op = try r.getU8(),
            .code = try r.getU8(),
        } },
        @backingInt(Tag.block_notice) => .{ .block_notice = .{
            .reason = try r.getU8(),
        } },
        @backingInt(Tag.presence_ping) => .{ .presence_ping = .{
            .seq = try r.getInt(u32),
            .ts_ms = try r.getInt(u64),
        } },
        @backingInt(Tag.presence_pong) => .{ .presence_pong = .{
            .seq = try r.getInt(u32),
            .ts_peer_ms = try r.getInt(u64),
        } },
        @backingInt(Tag.call_signal) => .{ .call_signal = .{
            .op = try r.getU8(),
            .call_id = try readId(&r),
        } },
        @backingInt(Tag.call_audio) => .{ .call_audio = .{
            .seq = try r.getInt(u32),
            .data = blk: {
                const data = try r.getBytes();
                if (data.len > max_audio_data) return error.BadLen;
                break :blk data;
            },
        } },
        @backingInt(Tag.join) => .{ .join = .{
            .bundle = (try r.getFixed(64))[0..64].*,
            .name = blk: {
                const nl = try r.getU8();
                if (nl == 0 or nl > max_join_name) return error.BadLen;
                break :blk try r.getFixed(nl);
            },
            .sig = (try r.getFixed(join_sig_len))[0..join_sig_len].*,
            .hmac = (try r.getFixed(join_hmac_len))[0..join_hmac_len].*,
        } },
        else => return error.UnknownTag,
    };

    if (!r.done()) return error.BadLen;
    return e;
}

fn readId(r: *codec.Reader) DecodeError![id_len]u8 {
    var id: [id_len]u8 = undefined;
    @memcpy(&id, try r.getFixed(id_len));
    return id;
}

const testing = std.testing;

/// Тестовый хелпер: массив `n` одинаковых байтов `value`.
fn filled(comptime n: usize, value: u8) [n]u8 {
    return @splat(value);
}

fn sampleText() Envelope {
    return .{ .text = .{
        .msg_id = .{
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
        },
        .ts_ms = 1_700_000_000_123,
        .body = "шёпот",
    } };
}

test "TEXT: roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const src = sampleText();
    const wire = try encode(&buf, src);
    try testing.expectEqual(encodedLen(src), wire.len);

    const back = try decode(wire);
    try testing.expectEqualSlices(u8, &src.text.msg_id, &back.text.msg_id);
    try testing.expectEqual(src.text.ts_ms, back.text.ts_ms);
    try testing.expectEqualStrings(src.text.body, back.text.body);
}

test "TEXT: раскладка байтов little-endian" {
    var buf: [64]u8 = undefined;
    var msg_id: [id_len]u8 = @splat(0);
    msg_id[0] = 1;
    msg_id[1] = 2;
    const wire = try encode(&buf, .{ .text = .{
        .msg_id = msg_id,
        .ts_ms = 1,
        .body = "ab",
    } });
    try testing.expectEqualSlices(u8, &.{
        0x10, // тег
        1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // msg_id
        1, 0, 0, 0, 0, 0, 0, 0, // ts_ms LE
        2, 0, // длина тела LE
        'a', 'b', // тело
    }, wire);
}

test "TEXT: пустое тело и максимум 4096" {
    var buf: [max_encoded_len]u8 = undefined;

    const empty: Envelope = .{ .text = .{ .msg_id = filled(id_len, 0), .ts_ms = 0, .body = "" } };
    const back_empty = try decode(try encode(&buf, empty));
    try testing.expectEqual(@as(usize, 0), back_empty.text.body.len);

    var body: [max_text_body]u8 = undefined;
    @memset(&body, 'x');
    const full: Envelope = .{ .text = .{ .msg_id = filled(id_len, 1), .ts_ms = 5, .body = &body } };
    const wire = try encode(&buf, full);
    try testing.expectEqual(max_encoded_len, wire.len);
    const back_full = try decode(wire);
    try testing.expectEqualSlices(u8, &body, back_full.text.body);
    try testing.expect(back_full.text.body.ptr == wire.ptr + 1 + id_len + 8 + 2); // срез wire, без копии
}

test "REACT: roundtrip" {
    var buf: [32]u8 = undefined;
    const src: Envelope = .{ .react = .{
        .msg_id = filled(id_len, 7),
        .op = react_add,
        .code = 42,
    } };
    const wire = try encode(&buf, src);
    try testing.expectEqual(@as(usize, 1 + id_len + 1 + 1), wire.len);

    const back = try decode(wire);
    try testing.expectEqualSlices(u8, &src.react.msg_id, &back.react.msg_id);
    try testing.expectEqual(react_add, back.react.op);
    try testing.expectEqual(@as(u8, 42), back.react.code);

    const rm: Envelope = .{ .react = .{ .msg_id = filled(id_len, 8), .op = react_remove, .code = 3 } };
    const back_rm = try decode(try encode(&buf, rm));
    try testing.expectEqual(react_remove, back_rm.react.op);
}

test "BLOCK_NOTICE: roundtrip" {
    var buf: [8]u8 = undefined;
    const wire = try encode(&buf, .{ .block_notice = .{ .reason = 5 } });
    try testing.expectEqualSlices(u8, &.{ 0x14, 5 }, wire);

    const back = try decode(wire);
    try testing.expectEqual(@as(u8, 5), back.block_notice.reason);
}

test "PRESENCE_PING/PONG: roundtrip" {
    var buf: [16]u8 = undefined;

    const ping: Envelope = .{ .presence_ping = .{ .seq = 0x11223344, .ts_ms = 0x0102030405060708 } };
    const back_ping = try decode(try encode(&buf, ping));
    try testing.expectEqual(@as(u32, 0x11223344), back_ping.presence_ping.seq);
    try testing.expectEqual(@as(u64, 0x0102030405060708), back_ping.presence_ping.ts_ms);

    const pong: Envelope = .{ .presence_pong = .{ .seq = 0x11223344, .ts_peer_ms = 0xF1F2F3F4F5F6F7F8 } };
    const back_pong = try decode(try encode(&buf, pong));
    try testing.expectEqual(@as(u32, 0x11223344), back_pong.presence_pong.seq);
    try testing.expectEqual(@as(u64, 0xF1F2F3F4F5F6F7F8), back_pong.presence_pong.ts_peer_ms);
}

test "CALL_SIGNAL: roundtrip всех опов" {
    var buf: [32]u8 = undefined;
    const ops = [_]u8{ call_offer, call_accept, call_reject, call_end };
    for (ops) |op| {
        const src: Envelope = .{ .call_signal = .{ .op = op, .call_id = filled(id_len, op) } };
        const wire = try encode(&buf, src);
        try testing.expectEqual(@as(usize, 1 + 1 + id_len), wire.len);

        const back = try decode(wire);
        try testing.expectEqual(op, back.call_signal.op);
        try testing.expectEqualSlices(u8, &src.call_signal.call_id, &back.call_signal.call_id);
    }
}

test "CALL_AUDIO: roundtrip" {
    var buf: [1 + 4 + 2 + max_audio_data]u8 = undefined;
    var data: [max_audio_data]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);

    const src: Envelope = .{ .call_audio = .{ .seq = 777, .data = &data } };
    const wire = try encode(&buf, src);
    try testing.expectEqual(@as(usize, 1 + 4 + 2 + max_audio_data), wire.len);

    const back = try decode(wire);
    try testing.expectEqual(@as(u32, 777), back.call_audio.seq);
    try testing.expectEqualSlices(u8, &data, back.call_audio.data);

    const silent: Envelope = .{ .call_audio = .{ .seq = 778, .data = "" } };
    const back_silent = try decode(try encode(&buf, silent));
    try testing.expectEqual(@as(usize, 0), back_silent.call_audio.data.len);
}

test "decode: неизвестный тег 0x7F -> UnknownTag" {
    const bytes: [8]u8 = @splat(0x7F);
    try testing.expectError(error.UnknownTag, decode(&bytes));
    try testing.expectError(error.UnknownTag, decode(&[_]u8{0x7F}));
    try testing.expectError(error.UnknownTag, decode(&[_]u8{0x12})); // дырка между тегами
}

test "decode: любой обрезанный кадр -> Truncated" {
    var buf: [max_encoded_len]u8 = undefined;
    const cases = [_]Envelope{
        sampleText(),
        .{ .react = .{ .msg_id = filled(id_len, 1), .op = react_add, .code = 1 } },
        .{ .block_notice = .{ .reason = 1 } },
        .{ .presence_ping = .{ .seq = 1, .ts_ms = 1 } },
        .{ .presence_pong = .{ .seq = 1, .ts_peer_ms = 1 } },
        .{ .call_signal = .{ .op = call_offer, .call_id = filled(id_len, 2) } },
        .{ .call_audio = .{ .seq = 1, .data = "abc" } },
    };
    for (cases) |case| {
        const wire = try encode(&buf, case);
        var cut: usize = 0;
        while (cut < wire.len) : (cut += 1) {
            try testing.expectError(error.Truncated, decode(wire[0..cut]));
        }
    }
}

test "decode: длина тела заявлена, байтов меньше -> Truncated" {
    var bytes: [1 + id_len + 8 + 2 + 3]u8 = undefined;
    var w = codec.Writer.init(&bytes);
    try w.put(@backingInt(Tag.text));
    try w.putFixed(&filled(id_len, 0));
    try w.putInt(u64, 0);
    try w.putInt(u16, 10); // обещано 10 байтов тела
    try w.putFixed("abc"); // есть только 3
    try testing.expectError(error.Truncated, decode(w.buf[0..w.pos]));
}

test "decode: лишний хвост после кадра -> BadLen" {
    var buf: [max_encoded_len + 1]u8 = undefined;
    const wire = try encode(buf[0..max_encoded_len], sampleText());
    buf[wire.len] = 0xFF;
    try testing.expectError(error.BadLen, decode(buf[0 .. wire.len + 1]));
}

test "decode: тело TEXT больше максимума -> BadLen" {
    var bytes: [1 + id_len + 8 + 2 + max_text_body + 1]u8 = undefined;
    var w = codec.Writer.init(&bytes);
    const overflow: [max_text_body + 1]u8 = @splat(0);
    try w.put(@backingInt(Tag.text));
    try w.putFixed(&filled(id_len, 0));
    try w.putInt(u64, 0);
    try w.putInt(u16, max_text_body + 1);
    try w.putFixed(&overflow);
    try testing.expectError(error.BadLen, decode(w.buf[0..w.pos]));
}

test "decode: DATA в CALL_AUDIO больше максимума -> BadLen" {
    var bytes: [1 + 4 + 2 + max_audio_data + 1]u8 = undefined;
    var w = codec.Writer.init(&bytes);
    const overflow: [max_audio_data + 1]u8 = @splat(0);
    try w.put(@backingInt(Tag.call_audio));
    try w.putInt(u32, 0);
    try w.putInt(u16, max_audio_data + 1);
    try w.putFixed(&overflow);
    try testing.expectError(error.BadLen, decode(w.buf[0..w.pos]));
}

test "encode: тело TEXT > 4096 -> TooBig, DATA > 1024 -> TooBig" {
    var big_buf: [max_encoded_len + 64]u8 = undefined;

    var big_body: [max_text_body + 1]u8 = undefined;
    @memset(&big_body, 'x');
    const big_text: Envelope = .{ .text = .{ .msg_id = filled(id_len, 0), .ts_ms = 0, .body = &big_body } };
    try testing.expectError(error.TooBig, encode(&big_buf, big_text));

    var big_data: [max_audio_data + 1]u8 = undefined;
    @memset(&big_data, 'y');
    const big_audio: Envelope = .{ .call_audio = .{ .seq = 0, .data = &big_data } };
    try testing.expectError(error.TooBig, encode(&big_buf, big_audio));
}

test "encode: слишком маленький буфер -> NoSpace" {
    var buf: [8]u8 = undefined;
    try testing.expectError(error.NoSpace, encode(&buf, sampleText()));
    try testing.expectError(error.NoSpace, encode(buf[0..0], sampleText()));
    // BLOCK_NOTICE занимает 2 байта — в один байт не влезает.
    try testing.expectError(error.NoSpace, encode(buf[0..1], .{ .block_notice = .{ .reason = 0 } }));
}

test "envelope: JOIN roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .join = .{
        .bundle = filled(64, 0x5A),
        .name = "mom",
        .sig = filled(64, 0x77),
        .hmac = filled(32, 0x33),
    } };
    const bytes = try encode(&buf, e);
    try testing.expectEqual(1 + 64 + 1 + 3 + 64 + 32, bytes.len);
    const back = try decode(bytes);
    try testing.expectEqualSlices(u8, &filled(64, 0x5A), &back.join.bundle);
    try testing.expectEqualStrings("mom", back.join.name);
    try testing.expectEqualSlices(u8, &filled(64, 0x77), &back.join.sig);
    try testing.expectEqualSlices(u8, &filled(32, 0x33), &back.join.hmac);
    // мусорный хвост — BadLen
    try testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));
}
