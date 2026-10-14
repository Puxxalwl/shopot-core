//! Аудио звонка: кадры 20 мс (16 кГц, моно, i16 = 640 байт), каждый кадр
//! шифруется своим ключом HKDF(call_secret, seq) — компрометация кадра не
//! раскрывает соседние. Транспорт уже даёт AEAD-слой, здесь свой контур.
//! На проводе кадр сжат IMA-ADPCM (4:1): провод = [codec u8][AEAD-блок];
//! codec 1 = PCM, 2 = ADPCM (164 байта на кадр, 72 кбит/с).
//!
//! Устройство: PCM подаётся/выводится через файловые дескрипторы (fifo/pipe).
//! Ноль OS-пакетов: микрофон подключается любой программой, которая умеет
//! писать сырой PCM в файл/поток (arecord, parec, pw-record). Пример:
//!   arecord -f S16_LE -r 8000 -c 1 --buffer-size=320 --pipe-in /tmp/mic
//!   aplay   -f S16_LE -r 8000 -c 1 /tmp/spk   (читает fifo)
//! Это интерфейс, а не заглушка: весь криптоконтур звука настоящих звонков.
const std = @import("std");
const linux = std.os.linux;
const shopot = @import("shopot");
const call_keys = shopot.crypto.call_keys;
const aead = shopot.crypto.aead;

pub const sample_rate = 16000;
pub const frame_ms = 20;
pub const frame_samples = sample_rate / 1000 * frame_ms; // 320 выборок
pub const frame_bytes = frame_samples * 2; // 640 байт i16 моно
pub const box_bytes = frame_bytes + aead.tag_length;
/// Кодек кадра на проводе (первый байт data CALL_AUDIO).
pub const codec_pcm: u8 = 1;
pub const codec_adpcm: u8 = 2;
/// ADPCM-блок одного кадра: заголовок 4 + 160 полубайтов.
pub const adpcm_block = 4 + frame_samples / 2; // 164

pub const CallOp = struct {
    /// CALL_SIGNAL op-коды.
    pub const offer: u8 = 0;
    pub const accept: u8 = 1;
    pub const reject: u8 = 2;
    pub const hangup: u8 = 3;
};

/// Шифрует кадр произвольной длины (PCM или ADPCM-блок):
/// out.len >= plain.len + aead.tag_length. Возвращает длину бокса.
pub fn sealFrame(out: []u8, call_secret: [32]u8, call_id: [16]u8, seq: u32, plain: []const u8) usize {
    const key = call_keys.keyFor(call_secret, seq);
    const nonce = aead.nonceFor(seq);
    aead.seal(out, plain, key, nonce, &call_id);
    return plain.len + aead.tag_length;
}

/// Расшифровывает кадр в plain_out (вместимость >= бокса минус тег).
/// Возвращает длину plaintext. Чужой/переигранный — ошибка Tampered.
pub fn openFrame(plain_out: []u8, call_secret: [32]u8, call_id: [16]u8, seq: u32, box_: []const u8) error{Tampered}!usize {
    if (box_.len < aead.tag_length or box_.len > plain_out.len + aead.tag_length) return error.Tampered;
    const key = call_keys.keyFor(call_secret, seq);
    const nonce = aead.nonceFor(seq);
    aead.open(plain_out, box_, key, nonce, &call_id) catch return error.Tampered;
    return box_.len - aead.tag_length;
}

/// Аудио-порт: два дескриптора (микрофон/динамик). Их даёт ОС или fifo.
pub const PcmPort = struct {
    mic_fd: std.posix.fd_t,
    spk_fd: std.posix.fd_t,

    /// Открыть пару fifo: <dir>/mic (читаем), <dir>/spk (пишем). Создаёт их.
    pub fn openFifos(dir: []const u8) !PcmPort {
        try makeFifo(dir, "mic");
        try makeFifo(dir, "spk");
        var pbuf: [512]u8 = undefined;
        const mic_path = try std.fmt.bufPrint(&pbuf, "{s}/mic", .{dir});
        // блокирующее открытие fifo на запись ждёт читателя — открываем
        // O_RDWR, чтобы не блокировать поток звонка
        const mic_fd = openRdwr(mic_path) catch return error.NoDevice;
        var sbuf: [512]u8 = undefined;
        const spk_path = try std.fmt.bufPrint(&sbuf, "{s}/spk", .{dir});
        const spk_fd = openRdwr(spk_path) catch {
            _ = linux.close(mic_fd);
            return error.NoDevice;
        };
        return .{ .mic_fd = mic_fd, .spk_fd = spk_fd };
    }

    fn openRdwr(path: []const u8) !std.posix.fd_t {
        var zbuf: [513]u8 = undefined;
        @memcpy(zbuf[0..path.len], path);
        zbuf[path.len] = 0;
        // O_RDWR=2 | O_NONBLOCK=0o4000
        const rc = linux.openat(@bitCast(@as(i32, -100)), @ptrCast(&zbuf), .{ .ACCMODE = .RDWR, .NONBLOCK = true }, 0);
        if (linux.errno(rc) != .SUCCESS) return error.NoDevice;
        return @intCast(rc);
    }

    fn makeFifo(dir: []const u8, name: []const u8) !void {
        var pbuf: [512]u8 = undefined;
        var zbuf: [513]u8 = undefined;
        const path = try std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ dir, name });
        @memcpy(zbuf[0..path.len], path);
        zbuf[path.len] = 0;
        _ = linux.unlink(@ptrCast(&zbuf));
        // mkfifo(path, 0600) = mknodat(AT_FDCWD, path, S_IFIFO|0600, 0)
        const mode: linux.mode_t = 0o010000 | 0o600;
        const rc = linux.mknodat(@bitCast(@as(i32, -100)), @ptrCast(&zbuf), mode, 0);
        if (linux.errno(rc) != .SUCCESS) return error.NoDevice;
    }

    pub fn deinit(self: *PcmPort) void {
        _ = linux.close(self.mic_fd);
        _ = linux.close(self.spk_fd);
    }

    /// Одна попытка чтения: сколько есть, столько и отдаёт (без дожидания).
    pub fn readPartial(self: *PcmPort, out: []u8) usize {
        const rc = linux.read(self.mic_fd, out.ptr, out.len);
        if (linux.errno(rc) != .SUCCESS) return 0;
        return @intCast(rc);
    }

    /// Вывести кадр на динамик.
    pub fn writeFrame(self: *PcmPort, data: []const u8) void {
        var sent: usize = 0;
        while (sent < data.len) {
            const rc = linux.write(self.spk_fd, data[sent..].ptr, data.len - sent);
            if (linux.errno(rc) != .SUCCESS or rc == 0) return;
            const n: usize = @intCast(rc);
            if (n == 0) return;
            sent += n;
        }
    }
};

test "audio: кадр шифруется/расшифровывается, чужой ключ отвергается" {
    const testing = std.testing;
    const secret: [32]u8 = @splat(9);
    const cid: [16]u8 = @splat(5);
    var frame: [frame_bytes]u8 = undefined;
    @memset(&frame, 0x55);
    var box_: [box_bytes]u8 = undefined;
    const sealed = sealFrame(&box_, secret, cid, 42, &frame);
    try testing.expectEqual(box_bytes, sealed);
    // чужой seq не расшифрует
    var out: [frame_bytes]u8 = undefined;
    try testing.expectError(error.Tampered, openFrame(&out, secret, cid, 43, &box_[0..sealed]));
    // свой — расшифрует побайтово; короткий ADPCM-блок тоже валиден
    try testing.expectEqual(frame_bytes, try openFrame(&out, secret, cid, 42, &box_[0..sealed]));
    try testing.expectEqualSlices(u8, &frame, &out);
    var ablock: [adpcm_block]u8 = undefined;
    @memset(&ablock, 0x33);
    var abox: [adpcm_block + aead.tag_length]u8 = undefined;
    const sealed2 = sealFrame(&abox, secret, cid, 7, &ablock);
    var out2: [adpcm_block]u8 = undefined;
    try testing.expectEqual(adpcm_block, try openFrame(&out2, secret, cid, 7, &abox[0..sealed2]));
    try testing.expectEqualSlices(u8, &ablock, &out2);
}
