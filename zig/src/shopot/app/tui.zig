//! Терминальный интерфейс: двухпанельный мессенджер на голом ANSI,
//! ноль зависимостей. Направление дизайна — плотная тёмная консоль:
//! один нейтральный ряд (тусклый = рамки/время), один акцент (cyan —
//! выбор и шапка), семантические цвета только для состояний
//! (green — online/я, yellow — звонок, red — блок). Bold только у имён
//! и активного элемента. Никаких других цветов и размеров.
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

/// Палитра (фиксированный набор — см. комментарий модуля).
pub const c = struct {
    pub const reset = "\x1b[0m";
    pub const dim = "\x1b[90m"; // рамки, время, подсказки, офлайн
    pub const bold = "\x1b[1m";
    pub const cyan = "\x1b[36m"; // акцент: выбор, шапка, имя собеседника
    pub const green = "\x1b[32m"; // онлайн, мои сообщения
    pub const yellow = "\x1b[33m"; // звонок
    pub const red = "\x1b[31m"; // блок
};

// ------------------------------------------------------------- модель ленты

/// Тип строки ленты.
pub const Kind = enum(u2) { mine, theirs, sys };

pub const name_max = 24;
pub const text_max = 200;
pub const ring_len = 128;

/// Одна строка переписки: фиксированные буферы, ноль аллокаций.
pub const ChatLine = struct {
    ts: i64 = 0, // epoch ms
    kind: Kind = .sys,
    name_buf: [name_max]u8 = @splat(0),
    name_len: u8 = 0,
    text_buf: [text_max]u8 = @splat(0),
    text_len: u16 = 0,

    pub fn name(self: *const ChatLine) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn text(self: *const ChatLine) []const u8 {
        return self.text_buf[0..self.text_len];
    }
};

/// Переписка одного контакта: кольцо строк + непрочитанные.
pub const Thread = struct {
    lines: [ring_len]ChatLine = @splat(.{}),
    head: u16 = 0,
    count: u16 = 0,
    unread: u16 = 0,

    /// Добавить строку (владелец обязан держать лок App).
    pub fn push(self: *Thread, ts: i64, kind: Kind, name: []const u8, txt: []const u8) void {
        const slot = &self.lines[self.head % ring_len];
        const nl = @min(name.len, name_max);
        @memcpy(slot.name_buf[0..nl], name[0..nl]);
        slot.name_len = @intCast(nl);
        const tl = @min(txt.len, text_max);
        @memcpy(slot.text_buf[0..tl], txt[0..tl]);
        slot.text_len = @intCast(tl);
        slot.ts = ts;
        slot.kind = kind;
        self.head +%= 1;
        if (self.count < ring_len) self.count += 1;
    }

    /// Строка по индексу (0 — самая старая из хранимых).
    pub fn at(self: *const Thread, i: u16) *const ChatLine {
        const idx = (self.head + ring_len - self.count + i) % ring_len;
        return &self.lines[idx];
    }
};

// ------------------------------------------------------------- форматтеры

/// Возраст последнего пакета: 0.4с / 12с / 5м / 2ч / —.
pub fn fmtAge(buf: []u8, age_ms: i64) []const u8 {
    if (age_ms < 0) return "—";
    if (age_ms < 1000) {
        return std.fmt.bufPrint(buf, "0.{d}с", .{@divTrunc(age_ms, 100)}) catch "—";
    }
    const s = @divTrunc(age_ms, 1000);
    if (s < 60) return std.fmt.bufPrint(buf, "{d}с", .{s}) catch "—";
    const m = @divTrunc(s, 60);
    if (m < 60) return std.fmt.bufPrint(buf, "{d}м", .{m}) catch "—";
    return std.fmt.bufPrint(buf, "{d}ч", .{@divTrunc(m, 60)}) catch "—";
}

/// Длительность звонка mm:ss.
pub fn fmtDur(buf: []u8, dur_ms: i64) []const u8 {
    const s = @divTrunc(dur_ms, 1000);
    const mm: u64 = @intCast(@divTrunc(s, 60));
    const ss: u64 = @intCast(@mod(s, 60));
    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}", .{ mm, ss }) catch "00:00";
}

/// Часы HH:MM локального времени (epoch ms + смещение tz в секундах).
pub fn fmtClock(buf: []u8, epoch_ms: i64, tz_off: i32) []const u8 {
    const total = @divTrunc(epoch_ms, 1000) + tz_off;
    const h = @mod(@divTrunc(total, 3600), 24);
    const m = @mod(@divTrunc(total, 60), 60);
    const hu: u64 = @intCast(h);
    const mu: u64 = @intCast(m);
    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}", .{ hu, mu }) catch "??:??";
}

/// Смещение локальной TZ (сек) из /etc/localtime (TZif v1/v2/v3).
/// При неудаче — 0 (UTC). Один вызов на старте, кэшируется вызывающим.
pub fn tzOffset() i32 {
    const rc = linux.openat(@bitCast(@as(i32, -100)), "/etc/localtime", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(rc) != .SUCCESS) return 0;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var buf: [4096]u8 = undefined;
    var off: usize = 0;
    while (off < buf.len) {
        const n = linux.read(fd, buf[off..].ptr, buf.len - off);
        if (linux.errno(n) != .SUCCESS) return 0;
        if (n == 0) break;
        off += @intCast(n);
    }
    if (off < 64 or !std.mem.eql(u8, buf[0..4], "TZif")) return 0;
    const ver = buf[4];
    const isutcnt = std.mem.readInt(u32, buf[20..24], .big);
    const isstdcnt = std.mem.readInt(u32, buf[24..28], .big);
    const leapcnt = std.mem.readInt(u32, buf[28..32], .big);
    const timecnt = std.mem.readInt(u32, buf[32..36], .big);
    const typecnt = std.mem.readInt(u32, buf[36..40], .big);
    const charcnt = std.mem.readInt(u32, buf[40..44], .big);
    var base: usize = 44;
    var tsize: usize = 4;
    if (ver == '2' or ver == '3') {
        const v1 = @as(usize, timecnt) * 5 + @as(usize, typecnt) * 6 + charcnt +
            @as(usize, leapcnt) * 8 + isstdcnt + isutcnt;
        base = 44 + v1 + 44; // заголовок v2 идёт сразу за блоком v1
        tsize = 8;
        if (base >= off) {
            // файл оборван — остаёмся на v1-данных
            base = 44;
            tsize = 4;
        }
    }
    const need = base + @as(usize, timecnt) * (tsize + 1) + @as(usize, typecnt) * 6;
    if (need > off or typecnt == 0) return 0;
    const now = nowMs();
    var best: ?usize = null;
    var i: usize = 0;
    while (i < timecnt) : (i += 1) {
        const t: i64 = if (tsize == 8)
            std.mem.readInt(i64, buf[base + i * tsize ..][0..8], .big)
        else
            @intCast(std.mem.readInt(i32, buf[base + i * tsize ..][0..4], .big));
        if (t * 1000 <= now) best = i else break;
    }
    const types_base = base + @as(usize, timecnt) * (tsize + 1);
    const ti: usize = if (best) |b| buf[base + @as(usize, timecnt) * tsize + b] else 0;
    if (ti >= typecnt) return 0;
    return std.mem.readInt(i32, buf[types_base + ti * 6 ..][0..4], .big);
}

/// Текущее epoch-время в мс (std.time в 0.17-срезе недоступен).
fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    const rc = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
    if (linux.errno(rc) != .SUCCESS) return 0;
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}

/// Обрезать строку до max_cols колонок по границам utf-8 рун.
pub fn trunc(dst: []u8, s: []const u8, max_cols: usize) []const u8 {
    var cols: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const l = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        if (i + l > s.len) break;
        if (cols + 1 > max_cols) break;
        cols += 1;
        i += l;
    }
    @memcpy(dst[0..i], s[0..i]);
    return dst[0..i];
}

// ------------------------------------------------------------- клавиатура

/// Неблокирующий читатель клавиш в raw-режиме.
pub const Keyboard = struct {
    orig: posix.termios,
    // остаток от прошлого read (вставка/быстрая печать одним куском):
    // одно нажатие за вызов, остальное разбирается в следующих poll-ах
    pending: [32]u8 = @splat(0),
    pending_len: usize = 0,

    pub fn init() !Keyboard {
        const orig = try posix.tcgetattr(0);
        var raw = orig;
        raw.lflag.ECHO = false;
        raw.lflag.ICANON = false;
        raw.lflag.ISIG = false;
        // VMIN=0/VTIME=0: read немедленно без ожидания
        raw.cc[@backingInt(linux.V.MIN)] = 0;
        raw.cc[@backingInt(linux.V.TIME)] = 0;
        try posix.tcsetattr(0, .FLUSH, raw);
        return .{ .orig = orig };
    }

    pub fn deinit(self: *Keyboard) void {
        posix.tcsetattr(0, .FLUSH, self.orig) catch {};
    }

    /// Читает одно нажатие (может быть последовательностью стрелки), ждёт до
    /// timeout_ms. Возвращает код: 'c' — юникод-символ (1-4 байта в buf),
    /// ключи up/down/enter/esc/tab/backspace — константы ниже.
    pub const Key = union(enum) {
        none,
        char: []const u8, // utf8 (до 4 байт), валиден до следующего вызова
        alt: u8, // Alt+<латинская буква> (ESC + буква): горячие клавиши
        up,
        down,
        enter,
        esc,
        backspace,
        ctrl_c,
        tab,
        unknown,
    };

    /// Разобрать ОДНО нажатие из buf; вернуть ключ и число съеденных байт.
    fn parseOne(buf: []const u8) struct { key: Key, used: usize } {
        if (buf.len == 0) return .{ .key = .none, .used = 0 };
        if (buf[0] == 3) return .{ .key = .ctrl_c, .used = 1 };
        if (buf[0] == 13 or buf[0] == 10) return .{ .key = .enter, .used = 1 };
        if (buf[0] == 9) return .{ .key = .tab, .used = 1 };
        if (buf[0] == 127 or buf[0] == 8) return .{ .key = .backspace, .used = 1 };
        if (buf[0] == 27) {
            if (buf.len >= 3 and buf[1] == '[') {
                return switch (buf[2]) {
                    'A' => .{ .key = .up, .used = 3 },
                    'B' => .{ .key = .down, .used = 3 },
                    else => .{ .key = .unknown, .used = 3 },
                };
            }
            // Alt+буква приходит как ESC + буква одним куском
            if (buf.len == 2 and buf[1] >= 'a' and buf[1] <= 'z') {
                return .{ .key = .{ .alt = buf[1] }, .used = 2 };
            }
            if (buf.len >= 2 and buf[1] >= 'a' and buf[1] <= 'z') {
                return .{ .key = .{ .alt = buf[1] }, .used = 2 };
            }
            return .{ .key = .esc, .used = 1 };
        }
        // юникод-символ: старшие биты ведущего байта определяют длину
        const len: usize = if (buf[0] < 0x80) 1 else if (buf[0] & 0xE0 == 0xC0) 2 else if (buf[0] & 0xF0 == 0xE0) 3 else 4;
        const l = @min(len, buf.len);
        @memcpy(keybuf[0..l], buf[0..l]);
        return .{ .key = .{ .char = keybuf[0..l] }, .used = l };
    }

    pub fn poll(self: *Keyboard, timeout_ms: i32) Key {
        // сначала до разбираем накопленное — без ожидания
        if (self.pending_len > 0) {
            const r = parseOne(self.pending[0..self.pending_len]);
            const used = r.used;
            const rest = self.pending_len - used;
            if (rest > 0) {
                std.mem.copyForwards(u8, self.pending[0..rest], self.pending[used .. used + rest]);
            }
            self.pending_len = rest;
            return r.key;
        }
        var pfd: [1]posix.pollfd = .{.{ .fd = 0, .events = posix.POLL.IN, .revents = 0 }};
        const n = posix.poll(&pfd, timeout_ms) catch return .unknown;
        if (n == 0) return .none;
        var buf: [32]u8 = undefined;
        const got = posix.read(0, &buf) catch return .unknown;
        if (got == 0) return .none;
        const r = parseOne(buf[0..got]);
        const used = r.used;
        if (used < got) {
            const rest = got - used;
            const rl = @min(rest, self.pending.len);
            @memcpy(self.pending[0..rl], buf[used .. used + rl]);
            self.pending_len = rl;
        }
        return r.key;
    }
};

var keybuf: [8]u8 = undefined;

// ------------------------------------------------------------- экран

pub fn enterScreen() void {
    // альтернативный экран, скрыть курсор, очистить
    writeAllRaw("\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
}

pub fn leaveScreen() void {
    writeAllRaw("\x1b[?25h\x1b[?1049l");
}

pub fn writeAllRaw(bytes: []const u8) void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(1, bytes[sent..].ptr, bytes.len - sent);
        if (linux.errno(rc) != .SUCCESS or rc == 0) return;
        sent += @intCast(rc);
    }
}

/// Определить размер терминала через TIOCGWINSZ.
pub fn termSize() struct { w: u16, h: u16 } {
    var ws: std.posix.winsize = undefined;
    const rc = linux.ioctl(0, linux.T.IOCGWINSZ, @intFromPtr(&ws));
    if (linux.errno(rc) != .SUCCESS or ws.col == 0) return .{ .w = 80, .h = 24 };
    return .{ .w = ws.col, .h = ws.row };
}

test "tui: клавиши распознаются" {
    const k: Keyboard.Key = .none;
    try std.testing.expect(k == .none);
}

test "tui: кольцо строк" {
    var th = Thread{};
    th.push(1000, .theirs, "eryn", "привет");
    th.push(2000, .mine, "я", "ответ");
    try std.testing.expectEqual(@as(u16, 2), th.count);
    try std.testing.expectEqualStrings("привет", th.at(0).text());
    try std.testing.expectEqualStrings("ответ", th.at(1).text());
    try std.testing.expectEqual(@as(i64, 2000), th.at(1).ts);
    // переполнение кольца
    for (0..ring_len + 5) |_| th.push(3, .sys, "", "x");
    try std.testing.expectEqual(@as(u16, ring_len), th.count);
}

test "tui: форматтеры" {
    var b: [16]u8 = undefined;
    try std.testing.expectEqualStrings("0.4с", fmtAge(&b, 450));
    try std.testing.expectEqualStrings("12с", fmtAge(&b, 12_000));
    try std.testing.expectEqualStrings("5м", fmtAge(&b, 300_000));
    try std.testing.expectEqualStrings("02:05", fmtDur(&b, 125_000));
    try std.testing.expectEqualStrings("09:00", fmtClock(&b, 9 * 3600 * 1000, 0));
    try std.testing.expectEqualStrings("12:30", fmtClock(&b, (12 * 3600 + 30 * 60) * 1000, 0));
    var d: [8]u8 = undefined;
    try std.testing.expectEqualStrings("ab", trunc(&d, "abcdef", 2));
}
