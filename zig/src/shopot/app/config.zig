//! Конфигурация ядра: режим сервера, маскировка транспорта, синхронизация
//! устройств. Хранится в шифрованном логе (kind cfg, последняя запись
//! побеждает), читается/пишется GUI-клиентом методами GET_CONFIG/SET_CONFIG.
//!
//! Формат blob (одинаков на проводе API, в логе и в событии CONFIG_CHANGED):
//!
//!     [ver u8 = 1][flags u32 LE][server_addr str16][tor_addr str16]
//!
//! flags (bit set = включено, остальные биты обязаны быть 0):
//!   bit0 server_mode   — весь трафик контактов идёт через свой релей-сервер
//!                        (cfg.server_addr, self-hosted; см. CORE-API.md)
//!   bit1 use_fake_tls  — маскировка транспорта под TLS 1.3 (по умолчанию)
//!   bit2 use_tor_mask  — исходящие прямые dial через Tor SOCKS5 (tor_addr)
//!   bit3 device_sync   — репликация записей БД на связанные устройства
//!                        (ближайший релей очереди, как outbox)
//!   bit4 lan_discovery — UDP-мультикаст анонсы/поиск в LAN
//!   bit5 autodial      — фоновый дозвон офлайн-контактов
//!
//! Правила как во всём проекте: little-endian, строки str16, без JSON.
//! Неизвестная версия blob или незарезервированные биты — ошибка декода
//! (fail-fast, никаких двусмысленных кодировок).

const std = @import("std");

/// Версия формата blob.
pub const wire_ver: u8 = 1;

/// Максимум длины адреса host:port.
pub const addr_max = 64;

/// Флаги конфигурации (битовые позиции в flags u32).
pub const flag_server_mode: u32 = 1 << 0;
pub const flag_use_fake_tls: u32 = 1 << 1;
pub const flag_use_tor_mask: u32 = 1 << 2;
pub const flag_device_sync: u32 = 1 << 3;
pub const flag_lan_discovery: u32 = 1 << 4;
pub const flag_autodial: u32 = 1 << 5;

/// Маска известных флагов: всё вне её обязано быть 0.
pub const flags_known: u32 = flag_server_mode | flag_use_fake_tls |
    flag_use_tor_mask | flag_device_sync | flag_lan_discovery |
    flag_autodial;

/// Ошибки кодирования/декодирования blob.
pub const Error = error{
    /// Буфер короче blob.
    NoSpace,
    /// Blob обрезан или структура неверна.
    BadFrame,
    /// Неизвестная версия формата.
    BadVersion,
    /// Установлены незарезервированные биты flags.
    BadFlags,
    /// Адрес не проходит правила (длина/формат/порт).
    BadAddr,
};

/// Конфигурация ядра. Поля-адреса — буферы host:port (не NUL-терминированы).
pub const Config = struct {
    /// Своим релеем становится указанный сервер: присутствие всех контактов
    /// держится на нём, сессии поднимаются через marker-спаривание.
    /// false → P2P/LAN как раньше. Требует непустого server_addr.
    server_mode: bool = false,
    /// Маскировка транспорта под TLS 1.3 (fake-TLS). Выключать только для
    /// сетей, режущих TLS-подобный трафик: остаётся обфускация + AEAD.
    /// Обе стороны обязаны совпадать, иначе рукопожатие не сойдётся.
    use_fake_tls: bool = true,
    /// Исходящие ПРЯМЫЕ dial (не релей) идут через Tor SOCKS5-прокси.
    /// Релей-подключения Tor не используют (релей и так скрывает IP).
    use_tor_mask: bool = false,
    /// Репликация новых записей БД на связанные устройства (device links).
    /// Работает только когда server_mode выключен (иначе сервер сам хранит
    /// доставку); очередь — как outbox: ждёт сессии с устройством.
    device_sync: bool = false,
    /// LAN-анонсы (мультикаст) и дозвон по анонсам.
    lan_discovery: bool = true,
    /// Фоновый автодозвон офлайн-контактов по сохранённым адресам.
    autodial: bool = true,

    server_addr_buf: [addr_max]u8 = @splat(0),
    server_addr_len: u8 = 0,
    tor_addr_buf: [addr_max]u8 = @splat(0),
    tor_addr_len: u8 = 0,

    /// Значения по умолчанию (tor-адрес предзаполнен стандартным портом
    /// локального Tor-демона; отключён, пока use_tor_mask = false).
    pub fn defaults() Config {
        var c = Config{};
        // стандартный порт локального Tor-демона: предзаполнен, но
        // выключен, пока use_tor_mask = false (константа — без ошибок)
        const tor = "127.0.0.1:9050";
        @memcpy(c.tor_addr_buf[0..tor.len], tor);
        c.tor_addr_len = tor.len;
        return c;
    }

    pub fn serverAddr(self: *const Config) []const u8 {
        return self.server_addr_buf[0..self.server_addr_len];
    }

    pub fn torAddr(self: *const Config) []const u8 {
        return self.tor_addr_buf[0..self.tor_addr_len];
    }

    /// Запомнить server-адрес (≤ addr_max, host:port). Порт 0/мусор — отказ.
    pub fn setServerAddr(self: *Config, addr: []const u8) Error!void {
        try checkAddr(addr);
        @memcpy(self.server_addr_buf[0..addr.len], addr);
        self.server_addr_len = @intCast(addr.len);
    }

    /// Запомнить tor-адрес (правила те же).
    pub fn setTorAddr(self: *Config, addr: []const u8) Error!void {
        try checkAddr(addr);
        @memcpy(self.tor_addr_buf[0..addr.len], addr);
        self.tor_addr_len = @intCast(addr.len);
    }

    /// Семантическая валидация: включённый режим требует адрес.
    pub fn validate(self: *const Config) Error!void {
        if (self.server_mode and self.serverAddr().len == 0) return error.BadAddr;
        if (self.use_tor_mask and self.torAddr().len == 0) return error.BadAddr;
    }

    /// Закодировать в buf (blob формата wire). Возвращает срез buf.
    /// Требует ≤ 1 + 4 + (2 + addr_max) × 2 байт.
    pub fn encode(self: *const Config, buf: []u8) Error![]const u8 {
        if (buf.len < blob_min) return error.NoSpace;
        var flags: u32 = 0;
        if (self.server_mode) flags |= flag_server_mode;
        if (self.use_fake_tls) flags |= flag_use_fake_tls;
        if (self.use_tor_mask) flags |= flag_use_tor_mask;
        if (self.device_sync) flags |= flag_device_sync;
        if (self.lan_discovery) flags |= flag_lan_discovery;
        if (self.autodial) flags |= flag_autodial;
        var n: usize = 0;
        buf[0] = wire_ver;
        n = 1;
        std.mem.writeInt(u32, buf[1..5], flags, .little);
        n = 5;
        n += try putStr16(buf[n..], self.serverAddr());
        n += try putStr16(buf[n..], self.torAddr());
        return buf[0..n];
    }

    /// Разобрать blob в self (полная замена полей). Валидирует структуру,
    /// версию, флаги и адреса; частичное применение исключено.
    pub fn decode(self: *Config, blob: []const u8) Error!void {
        if (blob.len < blob_min) return error.BadFrame;
        if (blob[0] != wire_ver) return error.BadVersion;
        const flags = std.mem.readInt(u32, blob[1..5], .little);
        if (flags & ~flags_known != 0) return error.BadFlags;
        var pos: usize = 5;
        const server = try getStr16(blob, &pos);
        const tor = try getStr16(blob, &pos);
        if (pos != blob.len) return error.BadFrame;
        // сначала адреса (с валидацией), потом флаги: при любом отказе
        // конфигурация остаётся нетронутой
        try checkAddrLen(server);
        try checkAddrLen(tor);
        var c = Config{};
        if (server.len > 0) try c.setServerAddr(server);
        if (tor.len > 0) try c.setTorAddr(tor);
        c.server_mode = flags & flag_server_mode != 0;
        c.use_fake_tls = flags & flag_use_fake_tls != 0;
        c.use_tor_mask = flags & flag_use_tor_mask != 0;
        c.device_sync = flags & flag_device_sync != 0;
        c.lan_discovery = flags & flag_lan_discovery != 0;
        c.autodial = flags & flag_autodial != 0;
        try c.validate();
        self.* = c;
    }
};

/// Минимальная длина blob: ver + flags + две пустые str16.
pub const blob_min: usize = 1 + 4 + 2 + 2;
/// Максимальная длина blob.
pub const blob_max: usize = 1 + 4 + (2 + addr_max) * 2;

fn putStr16(buf: []u8, s: []const u8) Error!usize {
    if (s.len > addr_max or buf.len < 2 + s.len) return error.NoSpace;
    std.mem.writeInt(u16, buf[0..2], @intCast(s.len), .little);
    @memcpy(buf[2..][0..s.len], s);
    return 2 + s.len;
}

fn getStr16(blob: []const u8, pos: *usize) Error![]const u8 {
    if (blob.len - pos.* < 2) return error.BadFrame;
    const len = std.mem.readInt(u16, blob[pos.*..][0..2], .little);
    if (len > addr_max) return error.BadFrame;
    if (blob.len - pos.* - 2 < len) return error.BadFrame;
    const s = blob[pos.* + 2 ..][0..len];
    pos.* += 2 + len;
    return s;
}

/// Адрес обязан быть host:port с портом 1..65535 (пустой — «не задан»).
fn checkAddrLen(s: []const u8) Error!void {
    if (s.len == 0) return;
    if (s.len > addr_max) return error.BadAddr;
    try checkAddr(s);
}

fn checkAddr(s: []const u8) Error!void {
    if (s.len == 0 or s.len > addr_max) return error.BadAddr;
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.BadAddr;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.BadAddr;
    if (port == 0) return error.BadAddr;
    if (colon == 0) return error.BadAddr; // пустой хост
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

const testing = std.testing;

test "defaults: fake_tls/lan/autodial включены, адреса sane" {
    const c = Config.defaults();
    try testing.expect(!c.server_mode);
    try testing.expect(c.use_fake_tls);
    try testing.expect(!c.use_tor_mask);
    try testing.expect(!c.device_sync);
    try testing.expect(c.lan_discovery);
    try testing.expect(c.autodial);
    try testing.expectEqualStrings("127.0.0.1:9050", c.torAddr());
    try testing.expectEqualStrings("", c.serverAddr());
}

test "encode/decode roundtrip со всеми полями" {
    var c = Config.defaults();
    c.server_mode = true;
    c.device_sync = true;
    c.use_fake_tls = false;
    try c.setServerAddr("10.0.0.1:9000");
    try c.setTorAddr("127.0.0.1:9150");
    var buf: [blob_max]u8 = undefined;
    const blob = try c.encode(&buf);
    try testing.expect(blob.len >= blob_min and blob.len <= blob_max);

    var back = Config.defaults();
    try back.decode(blob);
    try testing.expect(back.server_mode);
    try testing.expect(!back.use_fake_tls);
    try testing.expect(back.device_sync);
    try testing.expectEqualStrings("10.0.0.1:9000", back.serverAddr());
    try testing.expectEqualStrings("127.0.0.1:9150", back.torAddr());
}

test "decode: дефолтный blob (все нули)" {
    const blob = [_]u8{ wire_ver, 0, 0, 0, 0, 0, 0, 0, 0 };
    var c = Config{};
    try c.decode(&blob);
    try testing.expect(!c.server_mode);
    try testing.expect(!c.use_fake_tls);
    try testing.expectEqualStrings("", c.serverAddr());
    try testing.expectEqualStrings("", c.torAddr());
}

test "decode: обрезанный blob -> BadFrame" {
    var c = Config{};
    try testing.expectError(error.BadFrame, c.decode(&[_]u8{wire_ver}));
    try testing.expectError(error.BadFrame, c.decode(&[_]u8{ wire_ver, 0, 0, 0, 0, 0, 0 }));
    // лишний хвост
    var buf: [blob_max]u8 = undefined;
    const c1 = Config.defaults();
    const blob = try c1.encode(&buf);
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(testing.allocator);
    try bad.appendSlice(testing.allocator, blob);
    try bad.append(testing.allocator, 0xAA);
    try testing.expectError(error.BadFrame, c.decode(bad.items));
}

test "decode: неизвестная версия -> BadVersion" {
    var c = Config{};
    try testing.expectError(error.BadVersion, c.decode(&[_]u8{ 2, 0, 0, 0, 0, 0, 0, 0, 0 }));
}

test "decode: незарезервированный бит -> BadFlags" {
    var buf: [blob_max]u8 = undefined;
    const c0 = Config.defaults();
    const blob = try c0.encode(&buf);
    buf[1] = 0x40; // bit6 — зарезервирован
    var c = Config{};
    try testing.expectError(error.BadFlags, c.decode(blob));
}

test "decode: server_mode без адреса -> BadAddr" {
    var buf: [blob_max]u8 = undefined;
    const c0 = Config.defaults();
    const blob = try c0.encode(&buf);
    buf[1] |= @as(u8, @truncate(flag_server_mode));
    var c = Config{};
    try testing.expectError(error.BadAddr, c.decode(blob));
}

test "decode: битые адреса -> BadAddr" {
    var buf: [blob_max]u8 = undefined;
    const c0 = Config.defaults();
    const blob = try c0.encode(&buf);
    // tor-поле идёт после [ver][flags][server str16]; server по умолчанию
    // пуст → str16 tor начинается с buf[7]: [len 2][байты]
    std.mem.writeInt(u16, buf[7..9], 2, .little);
    buf[9] = 'a';
    buf[10] = ':';
    var c = Config{};
    // blob укорачиваем до новой границы поля: структура остаётся верной,
    // отказ даёт именно семантика адреса
    try testing.expectError(error.BadAddr, c.decode(blob[0..11]));
}

test "decode: отказ не мутирует конфигурацию" {
    var buf: [blob_max]u8 = undefined;
    var c = Config.defaults();
    c.use_fake_tls = false;
    const blob = try c.encode(&buf);
    buf[1] = 0x40;
    const before = c;
    try testing.expectError(error.BadFlags, c.decode(blob));
    try testing.expectEqual(before.use_fake_tls, c.use_fake_tls);
}

test "validate: use_tor_mask без адреса -> BadAddr" {
    var c = Config.defaults();
    c.tor_addr_len = 0;
    c.use_tor_mask = true;
    try testing.expectError(error.BadAddr, c.validate());
    c.setTorAddr("localhost:9050") catch unreachable;
    try c.validate();
}
