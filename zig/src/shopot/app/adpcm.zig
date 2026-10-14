//! IMA-ADPCM для голоса звонка: 4 бита на выборку вместо 16.
//! 20 мс @ 16 кГц моно = 320 выборок = 640 байт PCM -> блок 164 байта
//! (заголовок 4 + 160 полубайтов). С AEAD-тегом и байтом кодека кадр на
//! проводе: 181 байт/20 мс = 72 кбит/с вместо 131 кбит/с сырого PCM.
//! Стандартные таблицы IMA (RFC 3551 / WAV IMA-блоки); codec — чистая
//! композиция арифметики, без внешних зависимостей. Кодек с потерями —
//! для речи приёлемо, криптоконтур звонка не меняет.
const std = @import("std");

/// Таблица шагов IMA (квантование), 89 значений.
const step_table = [89]i32{
    7,     8,     9,     10,    11,    12,    13,    14,    16,    17,
    19,    21,    23,    25,    28,    31,    34,    37,    41,    45,
    50,    55,    60,    66,    73,    80,    88,    97,    107,   118,
    130,   143,   157,   173,   190,   209,   230,   253,   279,   307,
    337,   371,   408,   449,   494,   544,   598,   658,   724,   796,
    876,   963,   1060,  1166,  1282,  1411,  1552,  1707,  1878,  2066,
    2272,  2499,  2749,  3024,  3327,  3660,  4026,  4428,  4871,  5358,
    5894,  6484,  7132,  7845,  8630,  9493,  10442, 11487, 12635, 13899,
    15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
};

/// Изменение индекса шага по коду полубайта.
const index_table = [16]i8{ -1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8 };

pub const header_len = 4;
/// Заголовок блока: predictor i16 LE + step index u8 + резерв u8.
/// Кодирует samples_len байтов PCM (выборок samples_len/2) в out.
/// out.len >= header_len + samples_len/2/... — ровно 4 + ceil(n_samples/2).
/// Возвращает длину блока.
pub fn encodeBlock(out: []u8, pcm: []const u8) usize {
    const n_samples = pcm.len / 2;
    var predictor: i16 = if (n_samples > 0) readI16(pcm[0..2]) else 0;
    var index: u8 = 0;
    const u: u16 = @bitCast(predictor);
    out[0] = @truncate(u);
    out[1] = @truncate(u >> 8);
    out[2] = index;
    out[3] = 0;
    var pos: usize = header_len;
    var nib_pos: u8 = 0;
    var acc: u8 = 0;
    for (0..n_samples) |i| {
        const sample = readI16(pcm[i * 2 ..][0..2]);
        const code = encodeSample(sample, &predictor, &index);
        if (nib_pos == 0) {
            acc = code & 0x0f;
            nib_pos = 1;
        } else {
            out[pos] = acc | ((code & 0x0f) << 4);
            pos += 1;
            nib_pos = 0;
        }
    }
    if (nib_pos == 1) out[pos] = acc; // неполный байт при нечётном числе выборок
    return pos + @as(usize, nib_pos);
}

fn encodeSample(sample: i16, predictor: *i16, index: *u8) u8 {
    const step = step_table[index.*];
    var diff: i32 = @as(i32, sample) - @as(i32, predictor.*);
    var sign: u8 = 0;
    if (diff < 0) {
        sign = 8;
        diff = -diff;
    }
    var code: u8 = 0;
    var diffq: i32 = step >> 3;
    if (diff >= step) {
        code |= 4;
        diff -= step;
        diffq += step;
    }
    const half = step >> 1;
    if (diff >= half) {
        code |= 2;
        diff -= half;
        diffq += half;
    }
    const quarter = step >> 2;
    if (diff >= quarter) {
        code |= 1;
        diffq += quarter;
    }
    var next: i32 = @as(i32, predictor.*) + (if (sign != 0) -diffq else diffq);
    if (next > 32767) next = 32767;
    if (next < -32768) next = -32768;
    predictor.* = @intCast(next);
    var idx: i32 = @as(i32, index.*) + index_table[code];
    if (idx < 0) idx = 0;
    if (idx > 88) idx = 88;
    index.* = @intCast(idx);
    return code | sign;
}

/// Декодирует блок в out (PCM i16 LE); возвращает число записанных байтов.
pub fn decodeBlock(out: []u8, block: []const u8) usize {
    if (block.len < header_len) return 0;
    var predictor: i16 = @bitCast(readU16(block[0..2]));
    var index: u8 = block[2];
    var out_pos: usize = 0;
    for (block[header_len..]) |byte| {
        out_pos += decodeNib(out[out_pos..], byte & 0x0f, &predictor, &index);
        out_pos += decodeNib(out[out_pos..], (byte >> 4) & 0x0f, &predictor, &index);
    }
    return out_pos;
}

fn decodeNib(out: []u8, nib: u8, predictor: *i16, index: *u8) usize {
    if (out.len < 2) return 0;
    const step = step_table[index.*];
    var diffq: i32 = step >> 3;
    if (nib & 4 != 0) diffq += step;
    if (nib & 2 != 0) diffq += step >> 1;
    if (nib & 1 != 0) diffq += step >> 2;
    var next: i32 = @as(i32, predictor.*) + (if (nib & 8 != 0) -diffq else diffq);
    if (next > 32767) next = 32767;
    if (next < -32768) next = -32768;
    predictor.* = @intCast(next);
    var idx: i32 = @as(i32, index.*) + index_table[nib];
    if (idx < 0) idx = 0;
    if (idx > 88) idx = 88;
    index.* = @intCast(idx);
    const u: u16 = @bitCast(predictor.*);
    out[0] = @truncate(u);
    out[1] = @truncate(u >> 8);
    return 2;
}

fn readI16(b: *const [2]u8) i16 {
    return @bitCast(@as(u16, b[0]) | (@as(u16, b[1]) << 8));
}
fn readU16(b: *const [2]u8) u16 {
    return @as(u16, b[0]) | (@as(u16, b[1]) << 8);
}

test "adpcm: roundtrip 320 выборок, ошибка речевого диапазона" {
    // речеподобный сигнал: тон 220 Гц + обертон, амплитуда с плавным
    // нарастанием (речь не начинается с максимальной крутизны)
    var pcm: [640]u8 = undefined;
    for (0..320) |i| {
        const fi: f32 = @floatFromInt(i);
        const ramp = @min(1.0, fi / 40.0);
        const v: f32 = ramp * (@sin(fi / 16000.0 * 2.0 * 3.14159 * 220.0) * 5000.0 +
            0.3 * @sin(fi / 16000.0 * 2.0 * 3.14159 * 550.0) * 5000.0);
        const iv: i32 = @intFromFloat(v);
        const u: u16 = @bitCast(@as(i16, @intCast(iv)));
        pcm[i * 2] = @truncate(u);
        pcm[i * 2 + 1] = @truncate(u >> 8);
    }
    var block: [4 + 320 / 2 + 1]u8 = undefined;
    const n = encodeBlock(&block, &pcm);
    try std.testing.expectEqual(4 + 160, n);
    var back: [640]u8 = undefined;
    const m = decodeBlock(&back, block[0..n]);
    try std.testing.expectEqual(@as(usize, 640), m);
    var max_err: i32 = 0;
    for (0..320) |i| {
        const a: i32 = readI16(pcm[i * 2 ..][0..2]);
        const b: i32 = readI16(back[i * 2 ..][0..2]);
        const e: i32 = @intCast(@abs(a - b));
        if (e > max_err) max_err = e;
    }
    // после вхождения (20+ выборок) ошибка мала; допуск покрывает старт
    try std.testing.expect(max_err < 700);
}
