//! envelope — бинарные конверты протокола v3 (без JSON).
//!
//! Кадр: тег (u8), затем поля little-endian (см. codec.zig). Поля переменной
//! длины (тело TEXT, аудио CALL_AUDIO) имеют префикс длины u16. Декодер
//! возвращает union с типизированными полями; аллокаций нет — срезы `body`/
//! `data` указывают во входной буфер.
//!
//! Раскладка кадров:
//!   TEXT          0x10: msg_id: [16]u8, ts_ms: u64, body: u16 + байты (≤ 4096),
//!                       ents: u8-счётчик + записи форматирования (см. TextEntity)
//!   ACK           0x15: msg_id: [16]u8
//!   REACT         0x13: msg_id: [16]u8, op: u8, code: u32 (unicode code point)
//!   BLOCK_NOTICE  0x14: reason: u8
//!   PRESENCE_PING 0x20: seq: u32, ts_ms: u64
//!   PRESENCE_PONG 0x21: seq: u32, ts_peer_ms: u64
//!   CALL_SIGNAL   0x30: op: u8, call_id: [16]u8
//!   CALL_AUDIO    0x31: seq: u32, data: u16 + байты (≤ 1024)
//!   JOIN          0x40: bundle: [64]u8, name: u8 + байты (≤ 32),
//!                       sig: [64]u8, hmac: [32]u8
//!   PROFILE       0x42: name: u8 + байты (≤ 32), avatar_id: [16]u8
//!   CONTACT_CARD  0x43: name: u8 + байты (≤ 32), bundle: [64]u8,
//!                       addr: u16 + байты (≤ 64, пусто = неизвестен)
//!   RATCHET_KEY   0x44: epoch: u16, dh_pub: [32]u8 (PCS-ротация рэтчета)
//!   AVATAR        0x50: avatar_id: [16]u8, data: u16 + байты (≤ 16000)
//!   AVATAR_ACK   0x51: avatar_id: [16]u8
//!   AVATAR_REQ   0x52: avatar_id: [16]u8
//!   FILE_ACK     0x62: file_id: [16]u8, got: u32 (докачка)

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
    /// ACK доставки TEXT (высылается получателем каждого сообщения).
    ack = 0x15,
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
    /// PROFILE: имя и текущий avatar_id отправителя (эхо при каждом
    /// установлении сессии).
    profile = 0x42,
    /// CONTACT_CARD: визитная карточка третьего лица (имя + bundle +
    /// известный адрес) — SEND_CONTACT. Неизвестный тег на приёме
    /// отбрасывается: старые ядра просто пропускают карточку.
    contact_card = 0x43,
    /// RATCHET_KEY: свежий публичный X25519-ключ отправителя для DH-шага
    /// рэтчета. Обрабатывается сессией (до движка): обмен пабликами обеих
    /// сторон завершается совместным dhStep — новые цепочки, эпоха +1.
    ratchet_key = 0x44,
    /// AVATAR: байты аватара (контент-адресованы SHA-256[0..16]).
    avatar = 0x50,
    /// AVATAR_ACK: аватар получен и сохранён.
    avatar_ack = 0x51,
    /// AVATAR_REQ: просьба переслать аватар с этим id.
    avatar_req = 0x52,
    file_meta = 0x60,
    file_data = 0x61,
    /// FILE_ACK: сколько чанков файла уже принято (докачка с этой позиции).
    file_ack = 0x62,
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
/// Максимум entities форматирования на одно TEXT-сообщение.
pub const max_text_entities = 32;
/// Максимум длины value одной entity (совпадает с u8-длиной на проводе).
pub const max_entity_value = 255;
/// Максимум длины хвоста entities в TEXT: счётчик + записи.
pub const max_text_tail = 1 + max_text_entities * (6 + max_entity_value);
/// Максимум длины DATA в CALL_AUDIO.
pub const max_audio_data = 1024;
/// Максимум данных AVATAR: влезает в один obf-кадр класса 16384.
pub const max_avatar_data = 16000;
pub const max_file_chunk = 16000;
pub const max_file_name = 64;
/// Максимум длины имени в CONTACT_CARD.
pub const max_card_name = 32;
/// Максимум длины адреса в CONTACT_CARD (host:port).
pub const max_card_addr = 64;

/// Максимальная длина закодированного кадра (AVATAR с телом 16000).
pub const max_encoded_len = 1 + id_len + 4 + 2 + max_file_chunk;

/// Тип форматирования TEXT. Значения — контракт провода v4: новые типы
/// требуют бампа версии протокола (приём неизвестного кода = ошибка).
pub const EntityKind = enum(u8) {
    bold = 1,
    italic = 2,
    underline = 3,
    strikethrough = 4,
    spoiler = 5,
    /// Инлайн-код (`...`).
    code = 6,
    /// Блок кода; value — необязательный тег языка.
    pre = 7,
    /// Ссылка; value — URL (обязателен, ≤ max_entity_value).
    link = 8,
};

/// Одна entity форматирования: диапазон тела + тип + значение (стиль
/// Telegram MessageEntity). offset/len — БАЙТЫ UTF-8 в body (не code
/// points): в бинарном протоколе однозначно и без пересчёта; клиент при
/// рендере обязан резать по границам символов.
pub const TextEntity = struct {
    kind: EntityKind,
    /// Байтовое смещение начала в body.
    offset: u16,
    /// Длина диапазона в байтах (≥ 1).
    len: u16,
    /// Значение по kind: link — URL (обязателен), pre — язык (опционален),
    /// остальные — пусто. ≤ max_entity_value.
    value: []const u8 = &.{},
};

/// Ошибки entities: структура хвоста и правила (границы, сортировка,
/// соответствие value типу).
pub const EntitiesError = error{
    /// Хвост обрезан (не хватает байтов записи/value).
    Truncated,
    /// Лишние байты после последней записи.
    BadLen,
    /// Больше max_text_entities записей.
    TooMany,
    /// value длиннее max_entity_value.
    TooLong,
    /// len == 0 или offset+len выходит за body.
    OutOfRange,
    /// Записи не отсортированы по offset.
    Unsorted,
    /// value не соответствует kind (пустой URL, value у bold и т.п.).
    BadValue,
    /// Неизвестный код типа.
    BadKind,
};

/// Проверить типизированные entities против тела длиной body_len:
/// лимиты, границы, сортировку по offset, правила value. Пересечения
/// диапазонов (bold+italic на одном куске) разрешены. Вход API и движок
/// обязаны прогонять это до отправки; decode валидирует провод сам.
pub fn validateEntities(ents: []const TextEntity, body_len: usize) EntitiesError!void {
    if (ents.len > max_text_entities) return error.TooMany;
    var last_offset: ?u16 = null;
    for (ents) |e| {
        if (e.value.len > max_entity_value) return error.TooLong;
        if (e.len == 0) return error.OutOfRange;
        if (@as(usize, e.offset) + e.len > body_len) return error.OutOfRange;
        if (last_offset) |lo| {
            if (e.offset < lo) return error.Unsorted;
        }
        last_offset = e.offset;
        switch (e.kind) {
            .link => if (e.value.len == 0) return error.BadValue,
            .pre => {},
            .bold, .italic, .underline, .strikethrough, .spoiler, .code => if (e.value.len != 0) return error.BadValue,
        }
    }
}

/// Сериализовать entities в канонический хвост (провод TEXT, запись лога,
/// кадр API — один и тот же формат):
/// [count u8] × {[kind u8][offset u16][len u16][value_len u8][value]}.
/// Валидирует перед записью; NoSpace — буфер короче. Возвращает срез buf.
pub fn encodeEntitiesTail(buf: []u8, ents: []const TextEntity, body_len: usize) (codec.Writer.Error || EntitiesError)![]const u8 {
    try validateEntities(ents, body_len);
    var w = codec.Writer.init(buf);
    try w.put(@intCast(ents.len));
    for (ents) |e| {
        try w.put(@backingInt(e.kind));
        try w.putInt(u16, e.offset);
        try w.putInt(u16, e.len);
        try w.put(@intCast(e.value.len));
        try w.putFixed(e.value);
    }
    return w.buf[0..w.pos];
}

/// Разобрать и провалидировать хвост entities; весь `bytes` обязан быть
/// потреблён (лишний хвост — BadLen). Заполняет `out` (если задан):
/// не меньше count записей; value — срезы в `bytes`. Возвращает count.
pub fn parseEntities(bytes: []const u8, body_len: usize, out: ?[]TextEntity) EntitiesError!usize {
    if (bytes.len < 1) return error.Truncated;
    const count: usize = bytes[0];
    if (count > max_text_entities) return error.TooMany;
    var pos: usize = 1;
    var last_offset: ?u16 = null;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (bytes.len - pos < 6) return error.Truncated;
        const kind = std.enums.fromInt(EntityKind, bytes[pos]) orelse return error.BadKind;
        const offset = std.mem.readInt(u16, bytes[pos + 1 ..][0..2], .little);
        const len = std.mem.readInt(u16, bytes[pos + 3 ..][0..2], .little);
        const vlen: usize = bytes[pos + 5];
        pos += 6;
        if (vlen > max_entity_value) return error.TooLong;
        if (bytes.len - pos < vlen) return error.Truncated;
        const value = bytes[pos .. pos + vlen];
        pos += vlen;
        if (len == 0) return error.OutOfRange;
        if (@as(usize, offset) + len > body_len) return error.OutOfRange;
        if (last_offset) |lo| {
            if (offset < lo) return error.Unsorted;
        }
        last_offset = offset;
        switch (kind) {
            .link => if (vlen == 0) return error.BadValue,
            .pre => {},
            .bold, .italic, .underline, .strikethrough, .spoiler, .code => if (vlen != 0) return error.BadValue,
        }
        if (out) |o| o[i] = .{ .kind = kind, .offset = offset, .len = len, .value = value };
    }
    if (pos != bytes.len) return error.BadLen;
    return count;
}

/// TEXT (0x10): текстовое сообщение.
pub const Text = struct {
    /// Идентификатор сообщения.
    msg_id: [id_len]u8,
    /// Метка времени отправителя, мс.
    ts_ms: u64,
    /// Тело сообщения, ≤ 4096 байтов; срез входного буфера после decode.
    body: []const u8,
    /// Хвост форматирования: [count u8] × {entity} (см. encodeEntitiesTail /
    /// parseEntities). У отправителя — срез буфера вызывающего, построенный
    /// encodeEntitiesTail (encode валидирует его перед отправкой); пустой
    /// срез = форматирования нет (на проводе всё равно уйдёт байт счётчика
    /// ноль). У получателя — срез входного буфера, уже провалидирован decode.
    ents_tail: []const u8 = &.{},
};

/// REACT (0x13): реакция на сообщение.
pub const React = struct {
    /// Идентификатор сообщения.
    msg_id: [id_len]u8,
    /// 1 = добавить, 2 = снять (см. react_add/react_remove).
    op: u8,
    /// Реакция — unicode code point (U+0000..U+10FFFF), например 0x2764 = ❤.
    /// u32 LE в проводе; рендер (глиф/эмодзи) — задача клиента.
    code: u32,
};

/// ACK (0x15): подтверждение доставки TEXT с этим msg_id.
pub const Ack = struct {
    /// Идентификатор доставленного сообщения.
    msg_id: [id_len]u8,
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

/// PROFILE (0x42): имя и текущий avatar_id; отправляется ядром при каждом
/// установлении сессии, получатель обновляет имя контакта и знает, какой
/// аватар запрашивать (несовпадение id -> AVATAR_REQ).
pub const Profile = struct {
    /// Отображаемое имя отправителя, ≤ 32 байтов.
    name: []const u8,
    /// Текущий avatar_id отправителя; нули — аватара нет.
    avatar_id: [id_len]u8,
};

/// AVATAR (0x50): байты аватара (контент-адресованы id = SHA-256[0..16]).
pub const Avatar = struct {
    /// SHA-256(data)[0..16] — дедуп и адресация.
    avatar_id: [id_len]u8,
    /// Байты картинки, ≤ 16000; срез входного буфера после decode.
    data: []const u8,
};

/// AVATAR_ACK (0x51): аватар получен и сохранён.
pub const AvatarAck = struct {
    avatar_id: [id_len]u8,
};

/// AVATAR_REQ (0x52): просьба переслать аватар с этим id.
pub const AvatarReq = struct {
    avatar_id: [id_len]u8,
};

/// FILE_META (0x60): анонс передачи файла. file_id = SHA-256(файла)[0..16]
/// (контент-адресация, как у аватаров). Отправляется ДО чанков FILE_DATA.
pub const FileMeta = struct {
    file_id: [16]u8,
    /// Имя файла (UTF-8, без путей), <= 64 байтов.
    name: []const u8,
    /// Полный размер файла, байт.
    size: u32,
    /// SHA-256 всего файла: приём сверяет перед сохранением.
    sha: [32]u8,
};

/// FILE_DATA (0x61): чанк файла. Порядок задаёт seq (0..n-1); приём
/// собирает по порядку. Чанк <= max_file_chunk, каждый = один obf-кадр.
pub const FileData = struct {
    file_id: [16]u8,
    /// Номер чанка (порядковый, с нуля).
    seq: u32,
    /// Байты файла, <= max_file_chunk.
    data: []const u8,
};

/// CONTACT_CARD (0x43): визитная карточка контакта, пересланная третьей
/// стороной (метод SEND_CONTACT). Получатель видит имя, bundle и (если
/// отправителю известен) адрес; чтобы ДОБАВИТЬ этого человека, нужен его
/// собственный инвайт-код — карточка знакомит, не подключает.
pub const ContactCard = struct {
    /// Отображаемое имя карточки, ≤ 32 байтов; срез входного буфера после decode.
    name: []const u8,
    /// Полный bundle владельца карточки: enc_pk || sign_pk.
    bundle: [64]u8,
    /// Последний известный адрес host:port, ≤ 64 байтов; пусто — неизвестен.
    addr: []const u8,
};

/// RATCHET_KEY (0x44): PCS-ротация рэтчета. Отправитель сгенерировал свежую
/// X25519-пару для следующей эпохи и предъявляет публичную часть; получив
/// паблики ОБЕИХ сторон, каждая выполняет dhStep (свежий секрет свой,
/// fresh-паблик чужой) — цепочки пересоздаются, компрометация старых
/// цепочек больше не читает новые сообщения.
pub const RatchetKey = struct {
    /// Эпоха, на которую предназначен ключ = ratchet.epoch + 1 отправителя.
    epoch: u16,
    /// Свежий публичный X25519-ключ отправителя.
    dh_pub: [32]u8,
};

/// FILE_ACK (0x62): подтверждение приёма докачки. Приёмник шлёт его в
/// ответ на FILE_META (позиция: 0 / ожидаемый seq / всего чанков, если файл
/// уже сохранён) и далее каждые N чанков; отправитель возобновляет передачу
/// с последнего подтверждения (got = следующий ожидаемый seq).
pub const FileAck = struct {
    file_id: [16]u8,
    /// Чанков принято (следующий ожидаемый seq).
    got: u32,
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
    /// ACK (0x15).
    ack: Ack,
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
    /// PROFILE (0x42).
    profile: Profile,
    /// CONTACT_CARD (0x43).
    contact_card: ContactCard,
    /// RATCHET_KEY (0x44).
    ratchet_key: RatchetKey,
    /// AVATAR (0x50).
    avatar: Avatar,
    /// AVATAR_ACK (0x51).
    avatar_ack: AvatarAck,
    /// AVATAR_REQ (0x52).
    avatar_req: AvatarReq,
    file_meta: FileMeta,
    file_data: FileData,
    /// FILE_ACK (0x62).
    file_ack: FileAck,
};

/// Ошибки кодирования: мал буфер, payload превышает максимум протокола
/// либо хвост entities не проходит валидацию.
pub const EncodeError = codec.Writer.Error || error{ TooBig, BadEntities };

/// Точная длина закодированного кадра `e` в байтах — для подбора буфера.
pub fn encodedLen(e: Envelope) usize {
    return switch (e) {
        .text => |m| 1 + id_len + 8 + 2 + m.body.len + tailLen(m.ents_tail),
        .react, .call_signal => 1 + id_len + 1,
        .block_notice => 2,
        .ack => 1 + id_len,
        .presence_ping, .presence_pong => 1 + 4 + 8,
        .call_audio => |m| 1 + 4 + 2 + m.data.len,
        .join => |m| 1 + 64 + 1 + m.name.len + join_sig_len + join_hmac_len,
        .profile => |m| 1 + 1 + m.name.len + id_len,
        .contact_card => |m| 1 + 1 + m.name.len + 64 + 2 + m.addr.len,
        .ratchet_key => 1 + 2 + 32,
        .avatar => |m| 1 + id_len + 2 + m.data.len,
        .file_meta => |m| 1 + id_len + 1 + m.name.len + 4 + 32,
        .file_data => |m| 1 + id_len + 4 + 2 + m.data.len,
        .file_ack => 1 + id_len + 4,
        .avatar_ack, .avatar_req => 1 + id_len,
    };
}

/// Длина хвоста entities на проводе: пустой срез — один байт счётчика 0.
fn tailLen(tail: []const u8) usize {
    return if (tail.len == 0) 1 else tail.len;
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
            // хвост форматирования: пусто -> счётчик 0; иначе валидация
            // (границы/сортировка/правила value) и дословная запись
            if (m.ents_tail.len == 0) {
                try w.put(0);
            } else {
                _ = parseEntities(m.ents_tail, m.body.len, null) catch return error.BadEntities;
                try w.putFixed(m.ents_tail);
            }
        },
        .react => |m| {
            try w.put(@backingInt(Tag.react));
            try w.putFixed(&m.msg_id);
            try w.put(m.op);
            try w.putInt(u32, m.code);
        },
        .block_notice => |m| {
            try w.put(@backingInt(Tag.block_notice));
            try w.put(m.reason);
        },
        .ack => |m| {
            try w.put(@backingInt(Tag.ack));
            try w.putFixed(&m.msg_id);
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
        .profile => |m| {
            if (m.name.len > max_join_name) return error.TooBig;
            try w.put(@backingInt(Tag.profile));
            try w.put(@intCast(m.name.len));
            try w.putFixed(m.name);
            try w.putFixed(&m.avatar_id);
        },
        .contact_card => |m| {
            if (m.name.len > max_card_name) return error.TooBig;
            if (m.addr.len > max_card_addr) return error.TooBig;
            try w.put(@backingInt(Tag.contact_card));
            try w.put(@intCast(m.name.len));
            try w.putFixed(m.name);
            try w.putFixed(&m.bundle);
            try w.putBytes(m.addr);
        },
        .ratchet_key => |m| {
            try w.put(@backingInt(Tag.ratchet_key));
            try w.putInt(u16, m.epoch);
            try w.putFixed(&m.dh_pub);
        },
        .avatar => |m| {
            if (m.data.len > max_avatar_data) return error.TooBig;
            try w.put(@backingInt(Tag.avatar));
            try w.putFixed(&m.avatar_id);
            try w.putBytes(m.data);
        },
        .avatar_ack => |m| {
            try w.put(@backingInt(Tag.avatar_ack));
            try w.putFixed(&m.avatar_id);
        },
        .avatar_req => |m| {
            try w.put(@backingInt(Tag.avatar_req));
            try w.putFixed(&m.avatar_id);
        },
        .file_meta => |m| {
            if (m.name.len > max_file_name) return error.TooBig;
            try w.put(@backingInt(Tag.file_meta));
            try w.putFixed(&m.file_id);
            try w.put(@intCast(m.name.len));
            try w.putFixed(m.name);
            try w.putInt(u32, m.size);
            try w.putFixed(&m.sha);
        },
        .file_data => |m| {
            if (m.data.len > max_file_chunk) return error.TooBig;
            try w.put(@backingInt(Tag.file_data));
            try w.putFixed(&m.file_id);
            try w.putInt(u32, m.seq);
            try w.putBytes(m.data);
        },
        .file_ack => |m| {
            try w.put(@backingInt(Tag.file_ack));
            try w.putFixed(&m.file_id);
            try w.putInt(u32, m.got);
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
        @backingInt(Tag.text) => blk: {
            const msg_id = try readId(&r);
            const ts_ms = try r.getInt(u64);
            const body = bod: {
                const body = try r.getBytes();
                if (body.len > max_text_body) return error.BadLen;
                break :bod body;
            };
            // хвост entities: отсутствие байта счётчика (кадр v3) —
            // Truncated, битые записи — BadLen; валидный хвост потребляется
            // целиком, хвоста после него быть не может
            const tail = r.buf[r.pos..];
            _ = parseEntities(tail, body.len, null) catch |e| switch (e) {
                error.Truncated => return error.Truncated,
                else => return error.BadLen,
            };
            r.pos = r.buf.len;
            break :blk .{ .text = .{
                .msg_id = msg_id,
                .ts_ms = ts_ms,
                .body = body,
                .ents_tail = tail,
            } };
        },
        @backingInt(Tag.react) => .{ .react = .{
            .msg_id = try readId(&r),
            .op = try r.getU8(),
            .code = try r.getInt(u32),
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
        @backingInt(Tag.ack) => .{ .ack = .{
            .msg_id = try readId(&r),
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
        @backingInt(Tag.profile) => .{
            .profile = .{
                .name = blk: {
                    const nl = try r.getU8();
                    // 0 = имя не меняется (только avatar_id в этом PROFILE)
                    if (nl > max_join_name) return error.BadLen;
                    break :blk try r.getFixed(nl);
                },
                .avatar_id = (try r.getFixed(id_len))[0..id_len].*,
            },
        },
        @backingInt(Tag.contact_card) => .{ .contact_card = .{
            .name = blk: {
                const nl = try r.getU8();
                if (nl > max_card_name) return error.BadLen;
                break :blk try r.getFixed(nl);
            },
            .bundle = (try r.getFixed(64))[0..64].*,
            .addr = blk: {
                const addr = try r.getBytes();
                if (addr.len > max_card_addr) return error.BadLen;
                break :blk addr;
            },
        } },
        @backingInt(Tag.ratchet_key) => .{ .ratchet_key = .{
            .epoch = try r.getInt(u16),
            .dh_pub = (try r.getFixed(32))[0..32].*,
        } },
        @backingInt(Tag.avatar) => .{ .avatar = .{
            .avatar_id = (try r.getFixed(id_len))[0..id_len].*,
            .data = blk: {
                const data = try r.getBytes();
                if (data.len > max_avatar_data) return error.BadLen;
                break :blk data;
            },
        } },
        @backingInt(Tag.avatar_ack) => .{ .avatar_ack = .{
            .avatar_id = (try r.getFixed(id_len))[0..id_len].*,
        } },
        @backingInt(Tag.avatar_req) => .{ .avatar_req = .{
            .avatar_id = (try r.getFixed(id_len))[0..id_len].*,
        } },
        @backingInt(Tag.file_meta) => blk: {
            const file_id = try readId(&r);
            const name_len = try r.getU8();
            if (name_len > max_file_name) return error.BadLen;
            const name = try r.getFixed(name_len);
            const size = try r.getInt(u32);
            const sha = try r.getFixed(32);
            break :blk .{ .file_meta = .{
                .file_id = file_id,
                .name = name,
                .size = size,
                .sha = sha[0..32].*,
            } };
        },
        @backingInt(Tag.file_data) => blk: {
            const file_id = try readId(&r);
            const seq = try r.getInt(u32);
            const data = try r.getBytes();
            if (data.len > max_file_chunk) return error.BadLen;
            break :blk .{ .file_data = .{ .file_id = file_id, .seq = seq, .data = data } };
        },
        @backingInt(Tag.file_ack) => blk: {
            const file_id = try readId(&r);
            const got = try r.getInt(u32);
            break :blk .{ .file_ack = .{ .file_id = file_id, .got = got } };
        },
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
    // хвост: один байт счётчика 0
    try testing.expectEqual(@as(usize, 1), back.text.ents_tail.len);
    try testing.expectEqual(@as(u8, 0), back.text.ents_tail[0]);
    try testing.expectEqual(@as(usize, 0), try parseEntities(back.text.ents_tail, back.text.body.len, null));
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
        0, // счётчик entities = 0 (хвост есть всегда)
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
    try testing.expectEqual(1 + id_len + 8 + 2 + max_text_body + 1, wire.len);
    const back_full = try decode(wire);
    try testing.expectEqualSlices(u8, &body, back_full.text.body);
    try testing.expect(back_full.text.body.ptr == wire.ptr + 1 + id_len + 8 + 2); // срез wire, без копии
}

test "TEXT: entities — раскладка хвоста и roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    var tail_buf: [max_text_tail]u8 = undefined;

    const ents = [_]TextEntity{
        .{ .kind = .bold, .offset = 0, .len = 2 },
        .{ .kind = .link, .offset = 3, .len = 4, .value = "https://shopot.local" },
    };
    const tail = try encodeEntitiesTail(&tail_buf, &ents, "abcdefg".len);
    // [count][kind, offset LE, len LE, vlen, value...]
    var expected: [13 + 20]u8 = undefined;
    @memcpy(expected[0..13], &[_]u8{ 2, 1, 0, 0, 2, 0, 0, 8, 3, 0, 4, 0, 20 });
    @memcpy(expected[13..33], "https://shopot.local"[0..20]);
    try testing.expectEqualSlices(u8, &expected, tail);

    const src: Envelope = .{ .text = .{
        .msg_id = filled(id_len, 1),
        .ts_ms = 9,
        .body = "abcdefg",
        .ents_tail = tail,
    } };
    const wire = try encode(&buf, src);
    try testing.expectEqual(encodedLen(src), wire.len);

    const back = try decode(wire);
    try testing.expectEqualStrings(tail, back.text.ents_tail);
    var out: [max_text_entities]TextEntity = undefined;
    const n = try parseEntities(back.text.ents_tail, back.text.body.len, &out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(EntityKind.bold, out[0].kind);
    try testing.expectEqual(@as(u16, 0), out[0].offset);
    try testing.expectEqual(@as(u16, 2), out[0].len);
    try testing.expectEqualStrings("", out[0].value);
    try testing.expectEqual(EntityKind.link, out[1].kind);
    try testing.expectEqual(@as(u16, 3), out[1].offset);
    try testing.expectEqual(@as(u16, 4), out[1].len);
    try testing.expectEqualStrings("https://shopot.local", out[1].value);
}

test "entities: parseEntities отвергает мусор" {
    const blen: usize = 7;
    // выход за тело / len == 0
    try testing.expectError(error.OutOfRange, parseEntities(&[_]u8{ 1, 1, 0, 0, 9, 0, 0 }, blen, null));
    try testing.expectError(error.OutOfRange, parseEntities(&[_]u8{ 1, 1, 0, 0, 0, 0, 0 }, blen, null));
    // не отсортировано (offset 3, затем offset 1)
    try testing.expectError(error.Unsorted, parseEntities(&[_]u8{ 2, 1, 3, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0 }, blen, null));
    // link без URL
    try testing.expectError(error.BadValue, parseEntities(&[_]u8{ 1, 8, 0, 0, 2, 0, 0 }, blen, null));
    // bold со value
    try testing.expectError(error.BadValue, parseEntities(&[_]u8{ 1, 1, 0, 0, 2, 0, 1, 'x' }, blen, null));
    // неизвестный kind
    try testing.expectError(error.BadKind, parseEntities(&[_]u8{ 1, 99, 0, 0, 2, 0, 0 }, blen, null));
    // лишний байт после последней записи
    try testing.expectError(error.BadLen, parseEntities(&[_]u8{ 1, 1, 0, 0, 2, 0, 0, 0xFF }, blen, null));
    // счётчик больше max_text_entities
    try testing.expectError(error.TooMany, parseEntities(&[_]u8{33}, blen, null));
    // обрезано: нет счётчика / нет хвоста записи
    try testing.expectError(error.Truncated, parseEntities(&[_]u8{}, blen, null));
    try testing.expectError(error.Truncated, parseEntities(&[_]u8{ 1, 1, 0, 0, 2, 0 }, blen, null));
}

test "entities: encodeEntitiesTail — лимиты и буфер" {
    var tail_buf: [max_text_tail]u8 = undefined;
    // 33 записи — TooMany (валидация до записи в буфер)
    var ents: [max_text_entities + 1]TextEntity = undefined;
    for (&ents, 0..) |*e, i| e.* = .{ .kind = .bold, .offset = @intCast(i), .len = 1 };
    try testing.expectError(error.TooMany, encodeEntitiesTail(&tail_buf, &ents, max_text_body));
    // буфер короче хвоста — NoSpace
    var small: [3]u8 = undefined;
    try testing.expectError(error.NoSpace, encodeEntitiesTail(&small, &.{.{ .kind = .bold, .offset = 0, .len = 1 }}, 4));
    // граница тела — OutOfRange
    try testing.expectError(error.OutOfRange, encodeEntitiesTail(&tail_buf, &.{.{ .kind = .bold, .offset = 6, .len = 2 }}, 7));
}

test "TEXT: максимум entities — 32 link с value 255, тело 4096" {
    var buf: [max_encoded_len]u8 = undefined;
    var tail_buf: [max_text_tail]u8 = undefined;
    var value: [max_entity_value]u8 = undefined;
    @memset(&value, 'u');

    var ents: [max_text_entities]TextEntity = undefined;
    for (&ents, 0..) |*e, i| {
        e.* = .{ .kind = .link, .offset = @intCast(i * 128), .len = 1, .value = &value };
    }
    const tail = try encodeEntitiesTail(&tail_buf, &ents, max_text_body);
    try testing.expectEqual(@as(usize, 1 + max_text_entities * (6 + max_entity_value)), tail.len);

    var body: [max_text_body]u8 = undefined;
    @memset(&body, 'x');
    const src: Envelope = .{ .text = .{
        .msg_id = filled(id_len, 2),
        .ts_ms = 0,
        .body = &body,
        .ents_tail = tail,
    } };
    const wire = try encode(&buf, src);
    try testing.expectEqual(1 + id_len + 8 + 2 + max_text_body + max_text_tail, wire.len);

    const back = try decode(wire);
    var out: [max_text_entities]TextEntity = undefined;
    try testing.expectEqual(max_text_entities, try parseEntities(back.text.ents_tail, back.text.body.len, &out));
    try testing.expectEqualSlices(u8, &value, out[31].value);
}

test "TEXT: decode с битым хвостом entities -> BadLen, v3-кадр без хвоста -> Truncated" {
    var buf: [max_encoded_len]u8 = undefined;
    const tail = [_]u8{ 1, 1, 0, 0, 2, 0, 0 };
    const good = try encode(&buf, .{ .text = .{
        .msg_id = filled(id_len, 0),
        .ts_ms = 0,
        .body = "abcd",
        .ents_tail = &tail,
    } });
    // v3-кадр: хвост срезан целиком (нет байта счётчика) — Truncated
    try testing.expectError(error.Truncated, decode(good[0 .. good.len - tail.len]));
    // битый хвост: лишний байт после записи — BadLen
    var bytes: [1 + id_len + 8 + 2 + 4 + 8]u8 = undefined;
    var w = codec.Writer.init(&bytes);
    try w.put(@backingInt(Tag.text));
    try w.putFixed(&filled(id_len, 0));
    try w.putInt(u64, 0);
    try w.putBytes("abcd");
    try w.putFixed(&[_]u8{ 1, 1, 0, 0, 2, 0, 0, 0xFF });
    try testing.expectError(error.BadLen, decode(w.buf[0..w.pos]));
}

test "REACT: roundtrip" {
    var buf: [32]u8 = undefined;
    const src: Envelope = .{
        .react = .{
            .msg_id = filled(id_len, 7),
            .op = react_add,
            .code = 0x2764, // U+2764 = ❤
        },
    };
    const wire = try encode(&buf, src);
    try testing.expectEqual(@as(usize, 1 + id_len + 1 + 4), wire.len);

    const back = try decode(wire);
    try testing.expectEqualSlices(u8, &src.react.msg_id, &back.react.msg_id);
    try testing.expectEqual(react_add, back.react.op);
    try testing.expectEqual(@as(u32, 0x2764), back.react.code);

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

test "envelope: RATCHET_KEY roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .ratchet_key = .{
        .epoch = 0x0304,
        .dh_pub = filled(32, 0xA5),
    } };
    const bytes = try encode(&buf, e);
    try testing.expectEqual(@as(usize, 1 + 2 + 32), bytes.len);
    // тег 0x44, epoch u16 LE
    try testing.expectEqual(@as(u8, 0x44), bytes[0]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x04, 0x03 }, bytes[1..3]);

    const back = try decode(bytes);
    try testing.expectEqual(@as(u16, 0x0304), back.ratchet_key.epoch);
    try testing.expectEqualSlices(u8, &filled(32, 0xA5), &back.ratchet_key.dh_pub);
    // обрезанный/с хвостом
    try testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));
    var with_tail: [40]u8 = undefined;
    @memcpy(with_tail[0..bytes.len], bytes);
    with_tail[bytes.len] = 0;
    try testing.expectError(error.BadLen, decode(with_tail[0 .. bytes.len + 1]));
}

test "envelope: CONTACT_CARD roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .contact_card = .{
        .name = "алиса",
        .bundle = filled(64, 0x3B),
        .addr = "10.0.0.7:7779",
    } };
    const bytes = try encode(&buf, e);
    // тег 0x43, имя u8+байты, bundle 64, адрес u16+байты
    try testing.expectEqual(@as(u8, 0x43), bytes[0]);
    try testing.expectEqual(@as(usize, 1 + 1 + "алиса".len + 64 + 2 + "10.0.0.7:7779".len), bytes.len);

    const back = try decode(bytes);
    try testing.expectEqualStrings("алиса", back.contact_card.name);
    try testing.expectEqualSlices(u8, &filled(64, 0x3B), &back.contact_card.bundle);
    try testing.expectEqualStrings("10.0.0.7:7779", back.contact_card.addr);

    // обрезанный/с хвостом (до перезаписи буфера вторым конвертом)
    try testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));
    var with_tail: [128]u8 = undefined;
    @memcpy(with_tail[0..bytes.len], bytes);
    with_tail[bytes.len] = 0;
    try testing.expectError(error.BadLen, decode(with_tail[0 .. bytes.len + 1]));

    // пустой адрес валиден (адрес неизвестен)
    const e2 = Envelope{ .contact_card = .{
        .name = "б",
        .bundle = filled(64, 1),
        .addr = "",
    } };
    const b2 = try encode(&buf, e2);
    const back2 = try decode(b2);
    try testing.expectEqual(@as(usize, 0), back2.contact_card.addr.len);
}

test "envelope: ACK roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .ack = .{ .msg_id = filled(16, 0xC1) } };
    const bytes = try encode(&buf, e);
    try testing.expectEqual(1 + 16, bytes.len);
    const back = try decode(bytes);
    try testing.expectEqualSlices(u8, &filled(16, 0xC1), &back.ack.msg_id);
}

test "envelope: FILE_ACK roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .file_ack = .{ .file_id = @splat(0x6C), .got = 0xAABBCCDD } };
    const bytes = try encode(&buf, e);
    try testing.expectEqual(@as(usize, 1 + id_len + 4), bytes.len);
    try testing.expectEqual(@as(u8, 0x62), bytes[0]);
    // got u32 LE сразу после file_id
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDD, 0xCC, 0xBB, 0xAA }, bytes[17..21]);

    const back = try decode(bytes);
    try testing.expectEqualSlices(u8, &@as([id_len]u8, @splat(0x6C)), &back.file_ack.file_id);
    try testing.expectEqual(@as(u32, 0xAABBCCDD), back.file_ack.got);
    try testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));
    var with_tail: [32]u8 = undefined;
    @memcpy(with_tail[0..bytes.len], bytes);
    with_tail[bytes.len] = 0;
    try testing.expectError(error.BadLen, decode(with_tail[0 .. bytes.len + 1]));
}

test "envelope: FILE_META/FILE_DATA roundtrip" {
    const fid: [16]u8 = filled(id_len, 0xAB);
    var sha: [32]u8 = undefined;
    @memset(&sha, 0x5C);
    const m: Envelope = .{ .file_meta = .{
        .file_id = fid,
        .name = "отчёт.pdf",
        .size = 12345,
        .sha = sha,
    } };
    var buf: [max_encoded_len]u8 = undefined;
    const enc = try encode(&buf, m);
    const back = try decode(enc);
    try testing.expectEqualSlices(u8, &fid, &back.file_meta.file_id);
    try testing.expectEqualStrings("отчёт.pdf", back.file_meta.name);
    try testing.expectEqual(@as(u32, 12345), back.file_meta.size);
    try testing.expectEqualSlices(u8, &sha, &back.file_meta.sha);

    var data: [4096]u8 = undefined;
    @memset(&data, 0x77);
    const d: Envelope = .{ .file_data = .{ .file_id = fid, .seq = 3, .data = &data } };
    const enc2 = try encode(&buf, d);
    const back2 = try decode(enc2);
    try testing.expectEqualSlices(u8, &fid, &back2.file_data.file_id);
    try testing.expectEqual(@as(u32, 3), back2.file_data.seq);
    try testing.expectEqualSlices(u8, &data, back2.file_data.data);

    // имя > max_file_name -> TooBig
    var long_name: [max_file_name + 1]u8 = undefined;
    @memset(&long_name, 'x');
    const bad: Envelope = .{ .file_meta = .{ .file_id = fid, .name = &long_name, .size = 1, .sha = sha } };
    try testing.expectError(error.TooBig, encode(&buf, bad));
}
