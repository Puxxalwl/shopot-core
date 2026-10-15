//! Бинарный протокол ядрового API (UDS). Единственный контракт между
//! ядром shopot и GUI-клиентом; полная спецификация — docs/CORE-API.md.
//!
//! Правила (как во всём проекте): little-endian через std.mem.readInt/
//! writeInt, никаких JSON и varint. Все кадры имеют одинаковый 16-байтный
//! заголовок, строки на проводе — счётчик длины + сырые байты (str16/str32).
//! Текста-человека на проводе нет: только типизированные байтовые структуры
//! и машинные коды статусов/методов/событий (SCREAMING_SNAKE в документации).

const std = @import("std");

/// Магия кадра: "ZP" (0x5A50) в первых двух байтах.
pub const magic: u16 = 0x5A50;
/// Версия протокола на проводе.
pub const version: u8 = 1;
/// Максимальная длина payload одного кадра (1 МиБ).
pub const max_payload: u32 = 1024 * 1024;
/// Длина заголовка любого кадра.
pub const header_len = 16;

/// Версия API (команда GET_VERSION): semver [major, minor, patch].
/// Major меняется на несовместимых изменениях провода.
pub const api_version = [3]u16{ 1, 0, 0 };

/// Тип кадра.
pub const Kind = enum(u8) {
    /// Запрос клиента.
    request = 1,
    /// Ответ ядра на запрос (request_id echoed).
    response = 2,
    /// Событие ядра (рассылка всем клиентам).
    event = 3,
};

/// Методы API (u16 на проводе, имена SCREAMING_SNAKE — контракт).
pub const Method = enum(u16) {
    /// Закрыть соединение (не демон).
    CLOSE = 1,
    /// Версия API (проба готовности).
    GET_VERSION = 2,
    /// Свои публичные ключи: bundle + отпечаток.
    GET_IDENTITY = 3,
    /// Создать односторонний инвайт-код.
    CREATE_INVITE = 4,
    /// Погасить инвайт-код: добавить контакт (единственное действие держателя).
    ACCEPT_INVITE = 5,
    /// Список контактов.
    LIST_CONTACTS = 6,
    /// Отправить сообщение (контакт офлайн → очередь).
    SEND_MESSAGE = 7,
    /// Поставить реакцию на сообщение.
    SET_REACTION = 8,
    /// Снять реакцию со сообщения.
    REMOVE_REACTION = 9,
    /// История переписки с контактом.
    GET_HISTORY = 10,
    /// Одно сообщение (+ реакции) по msg_id.
    GET_MESSAGE = 11,
    /// Задать своё отображаемое имя.
    SET_NAME = 12,
    /// Задать свой аватар (байты inline).
    SET_AVATAR = 13,
    /// Текущий avatar_id контакта.
    GET_AVATAR_ID = 14,
    /// Передать файл контакту (путь в ФС пользователя ядра).
    SEND_FILE = 15,
    /// Инициировать звонок.
    START_CALL = 16,
    /// Принять входящий звонок.
    ANSWER_CALL = 17,
    /// Завершить/отклонить звонок.
    END_CALL = 18,
    /// Заблокировать контакт.
    BLOCK_CONTACT = 19,
    /// Разблокировать контакт.
    UNBLOCK_CONTACT = 20,
    /// Прямое подключение к контакту по адресу (обычно не нужно).
    CONNECT = 21,
    /// Слушать входящие подключения для контакта (обычно не нужно).
    LISTEN = 22,
};

/// Коды статуса ответа (u16 на проводе, имена SCREAMING_SNAKE — контракт;
/// человекотекста в ответах нет).
pub const Status = enum(u16) {
    /// Успех.
    OK = 0,
    /// Кадр сломан: магия/версия/длина или payload не разобран.
    BAD_FRAME = 1,
    /// Неизвестный метод.
    UNKNOWN_METHOD = 2,
    /// Неверные/неполные аргументы метода.
    BAD_ARGS = 3,
    /// Контакт с таким cid не существует.
    NO_CONTACT = 4,
    /// Контакт заблокирован (локально).
    CONTACT_BLOCKED = 5,
    /// Объект не найден (сообщение по msg_id и т.п.).
    NOT_FOUND = 6,
    /// Превышен лимит размера (тело, аватар, кадр, история).
    TOO_BIG = 7,
    /// Инвайт-код не разобран/не распознан.
    BAD_INVITE_CODE = 8,
    /// Реестр приглашений полон.
    TOO_MANY_INVITES = 9,
    /// Файл по пути не найден/не читается.
    FILE_NOT_FOUND = 10,
    /// Недопустимая реакция: codepoint вне U+0000..U+10FFFF.
    UNSUPPORTED_REACTION = 11,
    /// Нет живой сессии с контактом (требуется для некоторых операций).
    NO_SESSION = 12,
    /// Линия занята (звонок уже идёт).
    BUSY = 13,
    /// Активного звонка нет.
    NO_CALL = 14,
    /// Релей недоступен.
    NO_RELAY = 15,
    /// Транспорт не поднялся (dial/рукопожатие).
    TRANSPORT_FAILED = 16,
    /// Внутренняя ошибка ядра.
    INTERNAL = 255,
};

/// События ядра (u16 на проводе, имена SCREAMING_SNAKE — контракт).
pub const Event = enum(u16) {
    /// Входящее сообщение: [cid u32][msg_id 16][ts_ms u64][name str16][body str16].
    MESSAGE_RECEIVED = 1,
    /// ACK: сообщение доставлено на устройство пира: [cid u32][msg_id 16].
    MESSAGE_DELIVERED = 2,
    /// Presence: [cid u32][online u8][last_seen_ms i64].
    PRESENCE = 3,
    /// Реакция от пира: [cid u32][msg_id 16][op u8][codepoint u32][ts_ms u64].
    REACTION = 4,
    /// Перемена состояния звонка: [cid u32][call_id 16][state u8 (CallState)].
    CALL_STATE = 5,
    /// Байты аватара пира: [cid u32][avatar_id 16][data str16].
    AVATAR_RECEIVED = 6,
    /// Файл принят целиком: [cid u32][file_id 16][size u32][name str16].
    FILE_RECEIVED = 7,
    /// Контакт погасил наш инвайт: [cid u32][name str16].
    CONTACT_JOINED = 8,
    /// Профиль контакта (имя/аватар) изменился: [cid u32][name str16][avatar_id 16].
    CONTACT_PROFILE = 9,
    /// Пир заблокировал нас: [cid u32].
    BLOCKED_BY_PEER = 10,
    /// Файл передан целиком (все чанки подтверждены FILE_ACK):
    /// [cid u32][file_id 16][size u32][name str16].
    FILE_SENT = 11,
};

/// Состояние звонка для события CALL_STATE.
pub const CallState = enum(u8) {
    offer = 1,
    accept = 2,
    reject = 3,
    end = 4,
};

/// Заголовок кадра (одинаков для всех типов).
pub const Header = struct {
    kind: Kind,
    /// Метод (request/response) или событие (event).
    id: u16,
    /// Идентификатор запроса: клиент ставит, ядро повторяет в ответе.
    /// У событий всегда 0.
    request_id: u32,
    /// Статус (только response; у остальных OK).
    status: Status,
    payload_len: u32,
};

/// Записать заголовок кадра в out (16 байт, LE).
pub fn encodeHeader(out: *[header_len]u8, h: Header) void {
    std.mem.writeInt(u16, out[0..2], magic, .little);
    out[2] = version;
    out[3] = @backingInt(h.kind);
    std.mem.writeInt(u16, out[4..6], h.id, .little);
    std.mem.writeInt(u32, out[6..10], h.request_id, .little);
    std.mem.writeInt(u16, out[10..12], @backingInt(h.status), .little);
    std.mem.writeInt(u32, out[12..16], h.payload_len, .little);
}

/// Разобрать заголовок. null — неверная магия/версия.
pub fn decodeHeader(buf: *const [header_len]u8) ?Header {
    if (std.mem.readInt(u16, buf[0..2], .little) != magic) return null;
    if (buf[2] != version) return null;
    const kind = std.enums.fromInt(Kind, buf[3]) orelse return null;
    return .{
        .kind = kind,
        .id = std.mem.readInt(u16, buf[4..6], .little),
        .request_id = std.mem.readInt(u32, buf[6..10], .little),
        .status = std.enums.fromInt(Status, std.mem.readInt(u16, buf[10..12], .little)) orelse return null,
        .payload_len = std.mem.readInt(u32, buf[12..16], .little),
    };
}

/// Разбор payload запроса: курсор с проверкой границ.
/// Любое чтение за пределами — error.BadFrame.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    /// Остались ли непрочитанные байты.
    pub fn hasMore(self: *const Reader) bool {
        return self.pos < self.buf.len;
    }

    fn take(self: *Reader, n: usize) ![]const u8 {
        if (self.pos + n > self.buf.len) return error.BadFrame;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    pub fn readU8(self: *Reader) !u8 {
        return (try self.take(1))[0];
    }
    pub fn readU16(self: *Reader) !u16 {
        const b = try self.take(2);
        return std.mem.readInt(u16, b[0..2], .little);
    }
    pub fn readU32(self: *Reader) !u32 {
        const b = try self.take(4);
        return std.mem.readInt(u32, b[0..4], .little);
    }
    pub fn readU64(self: *Reader) !u64 {
        const b = try self.take(8);
        return std.mem.readInt(u64, b[0..8], .little);
    }
    pub fn readI64(self: *Reader) !i64 {
        const b = try self.take(8);
        return std.mem.readInt(i64, b[0..8], .little);
    }

    /// Фиксированный кусок байт (msg_id, bundle и т.п.).
    pub fn readBytes(self: *Reader, comptime n: usize) ![]const u8 {
        return self.take(n);
    }

    /// str16: [len u16][байты].
    pub fn readStr16(self: *Reader) ![]const u8 {
        const len = try self.readU16();
        return self.take(len);
    }

    /// str32: [len u32][байты].
    pub fn readStr32(self: *Reader) ![]const u8 {
        const len = try self.readU32();
        return self.take(len);
    }
};

/// Сборка payload ответа/события (аллокатор обязателен).
pub const Writer = struct {
    list: std.ArrayListUnmanaged(u8) = .empty,
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) Writer {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Writer) void {
        self.list.deinit(self.alloc);
    }

    /// Готовые байты payload.
    pub fn items(self: *const Writer) []const u8 {
        return self.list.items;
    }

    pub fn putU8(self: *Writer, v: u8) !void {
        try self.list.append(self.alloc, v);
    }
    pub fn putU16(self: *Writer, v: u16) !void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, .little);
        try self.list.appendSlice(self.alloc, &b);
    }
    pub fn putU32(self: *Writer, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try self.list.appendSlice(self.alloc, &b);
    }
    pub fn putU64(self: *Writer, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try self.list.appendSlice(self.alloc, &b);
    }
    pub fn putI64(self: *Writer, v: i64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(i64, &b, v, .little);
        try self.list.appendSlice(self.alloc, &b);
    }
    pub fn putBytes(self: *Writer, v: []const u8) !void {
        try self.list.appendSlice(self.alloc, v);
    }
    /// str16: [len u16][байты]; len > 65535 — error.BadArgs.
    pub fn putStr16(self: *Writer, v: []const u8) !void {
        if (v.len > std.math.maxInt(u16)) return error.BadArgs;
        try self.putU16(@intCast(v.len));
        try self.putBytes(v);
    }
    /// str32: [len u32][байты].
    pub fn putStr32(self: *Writer, v: []const u8) !void {
        try self.putU32(@intCast(v.len));
        try self.putBytes(v);
    }
};

test "header round-trip" {
    var buf: [header_len]u8 = undefined;
    encodeHeader(&buf, .{
        .kind = .response,
        .id = @backingInt(Method.SEND_MESSAGE),
        .request_id = 42,
        .status = .UNSUPPORTED_REACTION,
        .payload_len = 7,
    });
    const h = decodeHeader(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(Kind.response, h.kind);
    try std.testing.expectEqual(@as(u32, 42), h.request_id);
    try std.testing.expectEqual(Status.UNSUPPORTED_REACTION, h.status);
    try std.testing.expectEqual(@as(u32, 7), h.payload_len);
    try std.testing.expectEqual(@backingInt(Method.SEND_MESSAGE), h.id);
}

test "header rejects bad magic and version" {
    var buf: [header_len]u8 = undefined;
    @memset(&buf, 0);
    try std.testing.expect(decodeHeader(&buf) == null);
    encodeHeader(&buf, .{ .kind = .request, .id = 1, .request_id = 0, .status = .OK, .payload_len = 0 });
    buf[2] = 9;
    try std.testing.expect(decodeHeader(&buf) == null);
}

test "reader/writer round-trip" {
    const alloc = std.testing.allocator;
    var w = Writer.init(alloc);
    defer w.deinit();
    try w.putU8(0xAB);
    try w.putU32(0xDEADBEEF);
    try w.putU64(0x1122334455667788);
    try w.putBytes(&@as([16]u8, @splat(7)));
    try w.putStr16("привет");
    try w.putStr32("bytes");

    var r = Reader.init(w.items());
    try std.testing.expectEqual(@as(u8, 0xAB), try r.readU8());
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), try r.readU32());
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), try r.readU64());
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(7)), try r.readBytes(16));
    try std.testing.expectEqualStrings("привет", try r.readStr16());
    try std.testing.expectEqualStrings("bytes", try r.readStr32());
    try std.testing.expect(!r.hasMore());

    // чтение за границей — BadFrame
    try std.testing.expectError(error.BadFrame, r.readU8());
    try std.testing.expectError(error.BadFrame, r.readStr16());
}
