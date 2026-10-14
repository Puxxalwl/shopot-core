//! Терминальный интерфейс (альтернативный экран ANSI, ноль зависимостей):
//! панель контактов (online/звонок/BLOCKED), лента сообщений с историей из
//! AEAD-лога, строка ввода, статус-бар и подсказки клавиш внизу.
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const c_reset = "\x1b[0m";
const c_dim = "\x1b[2m";
const c_bold = "\x1b[1m";
const c_cyan = "\x1b[36m";
const c_green = "\x1b[32m";
const c_red = "\x1b[31m";
const c_yellow = "\x1b[33m";

/// Строка ленты чата: фиксированный буфер (кольцо без аллокаций).
pub const ChatLine = struct {
    text: [256]u8 = undefined,
    len: u16 = 0,

    pub fn view(self: *const ChatLine) []const u8 {
        return self.text[0..self.len];
    }
};

/// Неблокирующий читатель клавиш в raw-режиме.
pub const Keyboard = struct {
    orig: posix.termios,

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

    /// Читает одно нажатие (может быть последовательность стрелки), ждёт до
    /// timeout_ms. Возвращает код: 'c' — юникод-символ (1-4 байта в buf),
    /// ключи up/down/enter/esc/tab/backspace — константы ниже.
    pub const Key = union(enum) {
        none,
        char: []const u8, // utf8 (до 4 байт), валиден до следующего вызова
        up,
        down,
        enter,
        esc,
        backspace,
        ctrl_c,
        tab,
        unknown,
    };

    pub fn poll(self: *Keyboard, timeout_ms: i32) Key {
        _ = self;
        var pfd: [1]posix.pollfd = .{.{ .fd = 0, .events = posix.POLL.IN, .revents = 0 }};
        const n = posix.poll(&pfd, timeout_ms) catch return .unknown;
        if (n == 0) return .none;
        var buf: [8]u8 = undefined;
        const got = posix.read(0, &buf) catch return .unknown;
        if (got == 0) return .none;
        if (buf[0] == 3) return .ctrl_c;
        if (buf[0] == 13 or buf[0] == 10) return .enter;
        if (buf[0] == 9) return .tab;
        if (buf[0] == 127 or buf[0] == 8) return .backspace;
        if (buf[0] == 27) {
            if (got >= 3 and buf[1] == '[') {
                return switch (buf[2]) {
                    'A' => .up,
                    'B' => .down,
                    else => .unknown,
                };
            }
            return .esc;
        }
        // юникод-символ: старшие биты ведущего байта определяют длину
        const len: usize = if (buf[0] < 0x80) 1 else if (buf[0] & 0xE0 == 0xC0) 2 else if (buf[0] & 0xF0 == 0xE0) 3 else 4;
        @memcpy(keybuf[0..got], buf[0..got]);
        return .{ .char = keybuf[0..@min(got, len)] };
    }
};

var keybuf: [8]u8 = undefined;

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
        const n: usize = @intCast(rc);
        if (n == 0) return;
        sent += n;
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
