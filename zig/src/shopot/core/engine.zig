//! Engine: owns identity, contacts, blocklist, sessions, call and presence
//! state. All storage goes through the sealed log; nothing is ever plaintext
//! on disk. Callbacks fire from session threads — keep them fast or queue.
const std = @import("std");
const interfaces = @import("interfaces.zig");
const identity_mod = @import("../crypto/identity.zig");
const envelope = @import("../proto/envelope.zig");
const session_mod = @import("session.zig");

pub const EngineError = error{
    Blocked,
    NoSession,
    NoSpace,
    Store,
    OutOfMemory,
    TooBig,
    /// Слишком много файлов в передаче одновременно (file_tx_cap).
    TooManyFiles,
};

pub const Contact = struct {
    name: [32]u8 = @splat(0),
    name_len: u8 = 0,
    bundle: [64]u8 = @splat(0), // enc_pk || sign_pk
    online: bool = false,
    blocked: bool = false,
    /// Последний известный адрес host:port (для автодозвона офлайн-контактов).
    addr_buf: [64]u8 = @splat(0),
    addr_len: u8 = 0,
    addr_port: u16 = 0,
    /// Текущий avatar_id собеседника (SHA-256(данных)[0..16]); нули — нет.
    avatar_id: [16]u8 = @splat(0),

    /// Запомнить адрес (host без порта + порт). Порт 0 — адрес неизвестен.
    pub fn setAddr(self: *Contact, host: []const u8, port: u16) void {
        if (host.len == 0 or host.len > self.addr_buf.len or port == 0) return;
        @memcpy(self.addr_buf[0..host.len], host);
        self.addr_len = @intCast(host.len);
        self.addr_port = port;
    }

    /// host:port в буфер (для dial), null — адреса нет.
    pub fn addr(self: *const Contact, buf: []u8) ?[]const u8 {
        if (self.addr_len == 0 or self.addr_port == 0) return null;
        return std.fmt.bufPrint(buf, "{s}:{d}", .{ self.addr_buf[0..self.addr_len], self.addr_port }) catch null;
    }

    pub fn setName(self: *Contact, name: []const u8) void {
        const n = @min(name.len, self.name.len);
        @memcpy(self.name[0..n], name[0..n]);
        self.name_len = @intCast(n);
    }
    pub fn getName(self: *const Contact) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const Reaction = struct {
    msg_id: [16]u8,
    from: [64]u8, // peer bundle
    /// Операция: envelope.react_add / react_remove.
    op: u8,
    /// Unicode code point реакции (u32; U+0000..U+10FFFF).
    code: u32,
};

pub const Events = struct {
    ctx: *anyopaque = undefined,
    onText: ?*const fn (ctx: *anyopaque, from: *const Contact, msg_id: [16]u8, ts_ms: i64, body: []const u8) void = null,
    onReaction: ?*const fn (ctx: *anyopaque, from: *const Contact, r: Reaction) void = null,
    onPresence: ?*const fn (ctx: *anyopaque, from: *const Contact, online: bool, last_seen_ms: i64) void = null,
    /// Профиль пира обновился (эхо PROFILE: имя и avatar_id).
    onProfile: ?*const fn (ctx: *anyopaque, from: *const Contact, name: []const u8, avatar_id: [16]u8) void = null,
    onCallSignal: ?*const fn (ctx: *anyopaque, from: *const Contact, op: u8, call_id: [16]u8) void = null,
    onCallAudio: ?*const fn (ctx: *anyopaque, from: *const Contact, seq: u32, data: []const u8) void = null,
    onBlockedNotice: ?*const fn (ctx: *anyopaque, from: *const Contact) void = null,
    /// Доставка подтверждена: ACK по msg_id дошёл (сообщение дошло до пир-устройства).
    onDelivered: ?*const fn (ctx: *anyopaque, from: *const Contact, msg_id: [16]u8) void = null,
    /// Получен аватар: байты и id (приложение кладёт в кэш/лог).
    onAvatar: ?*const fn (ctx: *anyopaque, from: *const Contact, avatar_id: [16]u8, data: []const u8) void = null,
    /// Пир просит наш аватар с этим id (приложение перекачивает, если есть).
    onAvatarReq: ?*const fn (ctx: *anyopaque, from: *const Contact, avatar_id: [16]u8) void = null,
    /// Анонс файла FILE_META (приложение создаёт состояние приёма).
    onFileMeta: ?*const fn (ctx: *anyopaque, from: *const Contact, meta: envelope.FileMeta) void = null,
    /// Чанк FILE_DATA (приложение накапливает; по завершении — хэш и событие).
    onFileData: ?*const fn (ctx: *anyopaque, from: *const Contact, data: envelope.FileData) void = null,
    /// Файл передан целиком: все чанки подтверждены FILE_ACK-ами приёмника.
    onFileSent: ?*const fn (ctx: *anyopaque, from: *const Contact, file_id: [16]u8, size: u32, name: []const u8) void = null,
};

/// Запись outbox: TEXT, ждущий сессии/ACK.
pub const OutboxEntry = struct {
    cid: i64,
    msg_id: [16]u8,
    ts_ms: u64,
    /// Копия тела (alloc); свободается при ACK/истечении.
    body: []u8,
};

/// Передача файла в полёте (отправитель). Байты хранятся в движке до
/// подтверждения всех чанков — как outbox для TEXT: реконнект сессии
/// возобновляет с последнего подтверждённого чанка (FILE_ACK).
pub const FileTx = struct {
    cid: i64,
    file_id: [16]u8,
    /// Копия имени (alloc, ≤ max_file_name).
    name: []u8,
    /// Копия байтов файла (alloc, живёт до подтверждения всех чанков).
    data: []u8,
    sha: [32]u8,
    /// Чанков всего (ceil(data.len / max_file_chunk)).
    total: u32,
    /// Следующий чанк к отправке.
    next_seq: u32,
    /// Подтверждено приёмником (FILE_ACK.got) — точка докачки.
    last_ack: u32,
    /// Ждём позиционный FILE_ACK (наш FILE_META в полёте): следующий ACK
    /// переносит next_seq на позицию приёмника (докачка/перезапуск пира).
    await_pos: bool,
};

/// Окно передачи файла: неподтверждённых чанков в полёте не больше этого
/// (64 × 16000 ≈ 1 МБ) — ACK каждые 8 чанков держит окно живым.
pub const file_tx_window: u32 = 64;
/// Капа одновременных передач: больше — TooManyFiles (по 64 МБ максимум
/// на файл суммарно это верхний предел RAM движка на файлы).
pub const file_tx_cap = 8;

/// Окно дедупа входящих msg_id на контакт.
pub const seen_window = 64;
/// Капа outbox: старее — вытесняется.
pub const outbox_cap = 1000;
/// TTL записи outbox, мс (30 дней).
pub const outbox_ttl_ms: u64 = 30 * 24 * 3600 * 1000;

pub const Engine = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    id: identity_mod.Identity,
    ev: Events,

    contacts: std.ArrayListUnmanaged(Contact) = .empty,
    contact_ids: std.ArrayListUnmanaged(i64) = .empty, // stable small ids

    sessions: std.AutoHashMap(i64, *session_mod.Session),

    // presence: millisecond precision, passive
    last_seen_ms: std.AutoHashMap(i64, i64),

    /// Outbox: TEXT без сессии ждёт здесь (память + лог kind OUTBOX у приложения).
    outbox: std.ArrayListUnmanaged(OutboxEntry) = .empty,
    /// Передачи файлов в полёте (докачка FILE_ACK): file_id -> состояние.
    file_tx: std.ArrayListUnmanaged(FileTx) = .empty,
    /// Моё отображаемое имя (уходит в PROFILE).
    my_name: [32]u8 = @splat(0),
    my_name_len: u8 = 0,
    /// Мой текущий avatar_id (нулевое — аватара нет).
    my_avatar_id: [16]u8 = @splat(0),
    /// Дедуп входящих msg_id: cid -> последние seen_window id.
    seen: std.AutoHashMap(i64, std.ArrayListUnmanaged([16]u8)) = undefined,

    pub fn init(alloc: std.mem.Allocator, io: std.Io, id: identity_mod.Identity, ev: Events) Engine {
        return .{
            .alloc = alloc,
            .io = io,
            .id = id,
            .ev = ev,
            .sessions = std.AutoHashMap(i64, *session_mod.Session).init(alloc),
            .last_seen_ms = std.AutoHashMap(i64, i64).init(alloc),
            .seen = std.AutoHashMap(i64, std.ArrayListUnmanaged([16]u8)).init(alloc),
        };
    }

    pub fn deinit(self: *Engine) void {
        var it = self.sessions.valueIterator();
        while (it.next()) |s| {
            s.*.close();
        }
        self.sessions.deinit();
        self.contacts.deinit(self.alloc);
        self.contact_ids.deinit(self.alloc);
        self.last_seen_ms.deinit();
        for (self.outbox.items) |*e| self.alloc.free(e.body);
        self.outbox.deinit(self.alloc);
        for (self.file_tx.items) |*t| {
            std.crypto.secureZero(u8, &t.sha);
            self.alloc.free(t.name);
            self.alloc.free(t.data);
        }
        self.file_tx.deinit(self.alloc);
        var sit = self.seen.valueIterator();
        while (sit.next()) |list| list.deinit(self.alloc);
        self.seen.deinit();
    }

    pub fn addContact(self: *Engine, name: []const u8, bundle: [64]u8) !usize {
        var c = Contact{};
        c.setName(name);
        c.bundle = bundle;
        try self.contacts.append(self.alloc, c);
        const idx = self.contacts.items.len - 1;
        try self.contact_ids.append(self.alloc, @intCast(idx + 1));
        return idx;
    }

    pub fn findIndex(self: *Engine, id: i64) ?usize {
        if (id < 1) return null;
        const idx: usize = @intCast(id - 1);
        if (idx >= self.contacts.items.len) return null;
        return idx;
    }

    /// Куда попал TEXT после sendText + идентификатор (для истории/статусов).
    pub const SendOutcome = struct {
        result: SendResult,
        msg_id: [16]u8,
    };
    pub const SendResult = enum { sent, queued };

    /// Send text to a contact. Blocked peers are rejected locally.
    /// Нет сессии — сообщение уходит в outbox (доставим при появлении).
    pub fn sendText(self: *Engine, contact_id: i64, body: []const u8) EngineError!SendOutcome {
        const idx = self.findIndex(contact_id) orelse return EngineError.NoSession;
        if (self.contacts.items[idx].blocked) return EngineError.Blocked;
        var msg_id: [16]u8 = undefined;
        self.io.random(&msg_id);
        var ts_buf: [8]u8 = undefined;
        self.io.random(&ts_buf);
        const ts_ms: u64 = std.mem.readInt(u64, &ts_buf, .little) % 100_000_000_000_000;
        const env = envelope.Envelope{ .text = .{
            .msg_id = msg_id,
            .ts_ms = ts_ms,
            .body = body,
        } };
        if (self.sessions.get(contact_id)) |s| {
            // рэтчет-запечатанный TEXT (слой 2): msg_id/ts_ms наши — дедуп,
            // ACK и история согласованы; раньше уходил голым sendEnvelope
            // и слой рэтчета не задействовался вовсе
            s.sendSealedText(env) catch {
                // сессия умерла между проверкой и записью — в очередь
                self.outboxAppend(contact_id, msg_id, ts_ms, body) catch {};
                return .{ .result = .queued, .msg_id = msg_id };
            };
            return .{ .result = .sent, .msg_id = msg_id };
        }
        self.outboxAppend(contact_id, msg_id, ts_ms, body) catch return EngineError.OutOfMemory;
        return .{ .result = .queued, .msg_id = msg_id };
    }

    /// Положить TEXT в outbox (капа outbox_cap: старое вытесняется).
    fn outboxAppend(self: *Engine, cid: i64, msg_id: [16]u8, ts_ms: u64, body: []const u8) !void {
        if (body.len == 0 or body.len > envelope.max_text_body) return error.TooBig;
        if (self.outbox.items.len >= outbox_cap) {
            const old = self.outbox.orderedRemove(0);
            self.alloc.free(old.body);
        }
        const copy = try self.alloc.dupe(u8, body);
        self.outbox.append(self.alloc, .{ .cid = cid, .msg_id = msg_id, .ts_ms = ts_ms, .body = copy }) catch {
            self.alloc.free(copy);
            return error.OutOfMemory;
        };
    }

    /// Задать моё имя/avatar_id (эхо в PROFILE при каждом handshake).
    pub fn setMyProfile(self: *Engine, name: []const u8, avatar_id: [16]u8) void {
        const n = @min(name.len, self.my_name.len);
        @memcpy(self.my_name[0..n], name[0..n]);
        self.my_name_len = @intCast(n);
        self.my_avatar_id = avatar_id;
    }

    /// Моё имя (для PROFILE).
    pub fn myName(self: *Engine) []const u8 {
        return self.my_name[0..self.my_name_len];
    }

    /// Отправить PROFILE (имя + avatar_id) — при handshake/смене.
    pub fn sendProfile(self: *Engine, contact_id: i64) EngineError!void {
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .profile = .{
            .name = self.myName(),
            .avatar_id = self.my_avatar_id,
        } }) catch return EngineError.NoSession;
    }

    /// Отправить байты аватара (id = SHA-256(data)[0..16], считаем здесь).
    pub fn sendAvatar(self: *Engine, contact_id: i64, data: []const u8) EngineError![16]u8 {
        if (data.len == 0 or data.len > envelope.max_avatar_data) return EngineError.TooBig;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
        const id = digest[0..16].*;
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .avatar = .{ .avatar_id = id, .data = data } }) catch return EngineError.NoSession;
        return id;
    }

    /// Анонс файла: FILE_META до первого чанка. file_id/sha вычисляет
    /// вызывающий (контент-адресация SHA-256(file)[0..16]).
    pub fn sendFileMeta(self: *Engine, contact_id: i64, file_id: [16]u8, name: []const u8, size: u32, sha: [32]u8) EngineError!void {
        if (name.len > envelope.max_file_name) return EngineError.TooBig;
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .file_meta = .{ .file_id = file_id, .name = name, .size = size, .sha = sha } }) catch return EngineError.NoSession;
    }

    /// FILE_ACK: приёмник подтверждает позицию докачки (got чанков принято,
    /// got = следующий ожидаемый seq).
    pub fn sendFileAck(self: *Engine, contact_id: i64, file_id: [16]u8, got: u32) EngineError!void {
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .file_ack = .{ .file_id = file_id, .got = got } }) catch return EngineError.NoSession;
    }

    /// Чанк файла FILE_DATA: seq с нуля, подряд; data <= max_file_chunk.
    pub fn sendFileChunk(self: *Engine, contact_id: i64, file_id: [16]u8, seq: u32, data: []const u8) EngineError!void {
        if (data.len == 0 or data.len > envelope.max_file_chunk) return EngineError.TooBig;
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .file_data = .{ .file_id = file_id, .seq = seq, .data = data } }) catch return EngineError.NoSession;
    }

    /// Поставить файл в передачу с докачкой: байты КОПИРУЮТСЯ и живут в
    /// движке до подтверждения всех чанков; реконнект сессии возобновляет
    /// с последнего FILE_ACK. Сессии может не быть — передача ждёт её
    /// (resumeFileTx при установлении). Идемпотентно по (cid, file_id):
    /// контент-адресация, повторный вызов не дублирует.
    pub fn sendFile(self: *Engine, contact_id: i64, file_id: [16]u8, name: []const u8, bytes: []const u8, sha: [32]u8) EngineError!SendOutcome {
        const idx = self.findIndex(contact_id) orelse return EngineError.NoSession;
        if (self.contacts.items[idx].blocked) return EngineError.Blocked;
        if (name.len > envelope.max_file_name or bytes.len == 0 or bytes.len > std.math.maxInt(u32)) return EngineError.TooBig;
        for (self.file_tx.items) |*t| {
            if (t.cid == contact_id and std.mem.eql(u8, &t.file_id, &file_id)) {
                return .{ .result = .queued, .msg_id = file_id };
            }
        }
        if (self.file_tx.items.len >= file_tx_cap) return EngineError.TooManyFiles;
        const name_copy = self.alloc.dupe(u8, name) catch return EngineError.OutOfMemory;
        errdefer self.alloc.free(name_copy);
        const data_copy = self.alloc.dupe(u8, bytes) catch return EngineError.OutOfMemory;
        errdefer self.alloc.free(data_copy);
        const total: u32 = @intCast(@divTrunc(bytes.len + envelope.max_file_chunk - 1, envelope.max_file_chunk));
        self.file_tx.append(self.alloc, .{
            .cid = contact_id,
            .file_id = file_id,
            .name = name_copy,
            .data = data_copy,
            .sha = sha,
            .total = total,
            .next_seq = 0,
            .last_ack = 0,
            .await_pos = true,
        }) catch return EngineError.OutOfMemory;
        const t = &self.file_tx.items[self.file_tx.items.len - 1];
        self.fileTxAnnounce(t);
        self.fileTxPumpOne(t);
        const result: SendResult = if (t.next_seq > 0) .sent else .queued;
        return .{ .result = result, .msg_id = file_id };
    }

    /// FILE_META заново + позиция к последнему подтверждению: сессия
    /// поднялась, кадры мёртвой сессии не доедут. Приёмник ответит
    /// позиционным FILE_ACK и скорректирует точку докачки.
    pub fn resumeFileTx(self: *Engine, contact_id: i64) void {
        for (self.file_tx.items) |*t| {
            if (t.cid != contact_id) continue;
            t.next_seq = t.last_ack;
            t.await_pos = true;
            self.fileTxAnnounce(t);
            self.fileTxPumpOne(t);
        }
    }

    /// FILE_ACK от приёмника: позиция докачки. Первый ACK после FILE_META
    /// (await_pos) переносит next_seq на позицию приёмника — докачка или
    /// перезапуск пира; got МЕНЬШЕ last_ack в обычном режиме = приём
    /// сброшен (битый SHA) — заново с нуля; все чанки подтверждены →
    /// onFileSent и запись гасится.
    fn fileAck(self: *Engine, contact_id: i64, ack: envelope.FileAck) void {
        for (self.file_tx.items, 0..) |*t, i| {
            if (t.cid != contact_id) continue;
            if (!std.mem.eql(u8, &t.file_id, &ack.file_id)) continue;
            if (t.await_pos) {
                t.next_seq = @min(ack.got, t.total);
                t.await_pos = false;
            } else if (ack.got < t.last_ack) {
                // приёмник сбросил приём — заново с нуля
                t.next_seq = 0;
                t.last_ack = 0;
            }
            if (ack.got > t.last_ack) t.last_ack = @min(ack.got, t.total);
            if (t.last_ack >= t.total) {
                if (self.findIndex(contact_id)) |idx| {
                    if (self.ev.onFileSent) |cb| {
                        cb(self.ev.ctx, &self.contacts.items[idx], t.file_id, @intCast(t.data.len), t.name);
                    }
                }
                self.fileTxRemove(i);
                return;
            }
            self.fileTxPumpOne(t);
            return;
        }
        // чужой file_id — игнор (передачи уже нет/не было)
    }

    fn fileTxRemove(self: *Engine, i: usize) void {
        var t = self.file_tx.orderedRemove(i);
        std.crypto.secureZero(u8, &t.sha);
        self.alloc.free(t.name);
        self.alloc.free(t.data);
    }

    fn fileTxAnnounce(self: *Engine, t: *FileTx) void {
        self.sendFileMeta(t.cid, t.file_id, t.name, @intCast(t.data.len), t.sha) catch {};
    }

    /// Отправить чанки окна [next_seq, last_ack + file_tx_window).
    /// Сессии нет / ошибка записи — тихо: вернёмся при реконнекте.
    fn fileTxPumpOne(self: *Engine, t: *FileTx) void {
        const limit = @min(t.total, t.last_ack + file_tx_window);
        while (t.next_seq < limit) {
            const off: usize = @as(usize, t.next_seq) * envelope.max_file_chunk;
            const len: usize = @min(t.data.len - off, envelope.max_file_chunk);
            self.sendFileChunk(t.cid, t.file_id, t.next_seq, t.data[off..][0..len]) catch return;
            t.next_seq += 1;
        }
    }

    /// Сессия поднялась: слить outbox по cid (идемпотентно — дедуп на приёме).
    /// Пачками по 64 конверта: sendSealedTexts запечатывает пачку и кладёт
    /// её в один obf-кадр (коалесценция мелких конвертов, ROADMAP P1) —
    /// реконнект с очередью не стоит кадр 128+26 байт на каждое сообщение.
    /// Сбой пачки оставляет записи нетронутыми: повтор идемпотентен дедупом.
    pub fn flushOutbox(self: *Engine, contact_id: i64) void {
        if (self.findIndex(contact_id) == null) return;
        const s = self.sessions.get(contact_id) orelse return;
        var batch: [64]envelope.Envelope = undefined;
        var n: usize = 0;
        var i: usize = 0;
        while (i < self.outbox.items.len) {
            const e = self.outbox.items[i];
            const fresh = e.ts_ms + outbox_ttl_ms > @as(u64, @intCast(self.nowMs()));
            if (e.cid != contact_id or !fresh) {
                if (e.cid == contact_id and !fresh) {
                    const old = self.outbox.orderedRemove(i);
                    self.alloc.free(old.body);
                    continue;
                }
                i += 1;
                continue;
            }
            batch[n] = .{ .text = .{ .msg_id = e.msg_id, .ts_ms = e.ts_ms, .body = e.body } };
            n += 1;
            i += 1;
            if (n == batch.len) {
                s.sendSealedTexts(batch[0..n]) catch return;
                n = 0;
            }
        }
        if (n > 0) s.sendSealedTexts(batch[0..n]) catch {};
    }

    /// ACK дошёл: выкинуть запись outbox, событие onDelivered.
    fn outboxAcked(self: *Engine, cid: i64, msg_id: [16]u8, c: *const Contact) void {
        var i: usize = 0;
        while (i < self.outbox.items.len) {
            if (self.outbox.items[i].cid == cid and std.mem.eql(u8, &self.outbox.items[i].msg_id, &msg_id)) {
                const old = self.outbox.orderedRemove(i);
                self.alloc.free(old.body);
            } else {
                i += 1;
            }
        }
        if (self.ev.onDelivered) |cb| cb(self.ev.ctx, c, msg_id);
    }

    /// Дедуп: true — уже видели этот msg_id от контакта.
    fn seenHas(self: *Engine, cid: i64, msg_id: [16]u8) bool {
        const gop = self.seen.getOrPut(cid) catch return false;
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const list = gop.value_ptr;
        for (list.items) |m| {
            if (std.mem.eql(u8, &m, &msg_id)) return true;
        }
        return false;
    }

    fn seenPut(self: *Engine, cid: i64, msg_id: [16]u8) void {
        const gop = self.seen.getOrPut(cid) catch return;
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const list = gop.value_ptr;
        list.append(self.alloc, msg_id) catch return;
        if (list.items.len > seen_window) _ = list.orderedRemove(0);
    }

    pub fn react(self: *Engine, contact_id: i64, msg_id: [16]u8, op: u8, code: u32) EngineError!void {
        const idx = self.findIndex(contact_id) orelse return EngineError.NoSession;
        if (self.contacts.items[idx].blocked) return EngineError.Blocked;
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .react = .{ .msg_id = msg_id, .op = op, .code = code } }) catch return EngineError.NoSession;
    }

    pub fn block(self: *Engine, contact_id: i64) EngineError!void {
        const idx = self.findIndex(contact_id) orelse return EngineError.NoSession;
        self.contacts.items[idx].blocked = true;
        if (self.sessions.get(contact_id)) |s| {
            s.sendEnvelope(.{ .block_notice = .{ .reason = 0 } }) catch {};
            s.close();
            _ = self.sessions.remove(contact_id);
        }
    }

    pub fn unblock(self: *Engine, contact_id: i64) EngineError!void {
        const idx = self.findIndex(contact_id) orelse return EngineError.NoSession;
        self.contacts.items[idx].blocked = false;
    }

    pub fn callSignal(self: *Engine, contact_id: i64, op: u8, call_id: [16]u8) EngineError!void {
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .call_signal = .{ .op = op, .call_id = call_id } }) catch return EngineError.NoSession;
    }

    pub fn callAudio(self: *Engine, contact_id: i64, seq: u32, data: []const u8) EngineError!void {
        const s = self.sessions.get(contact_id) orelse return EngineError.NoSession;
        s.sendEnvelope(.{ .call_audio = .{ .seq = seq, .data = data } }) catch return EngineError.NoSession;
    }

    /// Millisecond wall time through the injected io.
    pub fn nowMs(self: *Engine) i64 {
        const ts = std.Io.Clock.now(.real, self.io);
        return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
    }

    pub fn markSeen(self: *Engine, contact_id: i64, now_ms: i64) void {
        self.last_seen_ms.put(contact_id, now_ms) catch {};
        const idx = self.findIndex(contact_id) orelse return;
        const was = self.contacts.items[idx].online;
        self.contacts.items[idx].online = true;
        if (!was) {
            if (self.ev.onPresence) |cb|
                cb(self.ev.ctx, &self.contacts.items[idx], true, now_ms);
        }
    }

    pub fn lastSeen(self: *Engine, contact_id: i64) ?i64 {
        return self.last_seen_ms.get(contact_id);
    }

    /// Engine-side envelope dispatch. Runs on a session read thread.
    pub fn dispatch(self: *Engine, contact_id: i64, env: envelope.Envelope) void {
        self.dispatchEvent(contact_id, env);
    }

    /// dispatch без привязки к сессии (тесты гоняют машину FILE_ACK
    /// напрямую). Смысл тот же: дедуп текстов, ACK outbox, file_tx.
    pub fn dispatchEvent(self: *Engine, contact_id: i64, env: envelope.Envelope) void {
        const idx = self.findIndex(contact_id) orelse return;
        const c = &self.contacts.items[idx];
        if (c.blocked) return; // hard ignore for blocked peers
        switch (env) {
            // RATCHET_KEY до движка не доходит: сессия съедает его сама
            // (крипто-состояние рэтчета), но exhaustiveness требует ветку
            .ratchet_key => {},
            .text => |t| {
                if (self.seenHas(contact_id, t.msg_id)) {
                    // повтор после реконнекта — уже доставлено; зеркальный ACK
                    if (self.sessions.get(contact_id)) |sess| {
                        sess.sendEnvelope(.{ .ack = .{ .msg_id = t.msg_id } }) catch {};
                    }
                    return;
                }
                self.seenPut(contact_id, t.msg_id);
                if (self.ev.onText) |cb| cb(self.ev.ctx, c, t.msg_id, @intCast(t.ts_ms), t.body);
                if (self.sessions.get(contact_id)) |sess| {
                    sess.sendEnvelope(.{ .ack = .{ .msg_id = t.msg_id } }) catch {};
                }
            },
            .ack => |a| {
                self.outboxAcked(contact_id, a.msg_id, c);
            },
            .profile => |pr| {
                // эхо: обновляем имя и запоминаемый avatar_id пир-а;
                // пустое имя = не менять; расхождение id -> просим перекачать
                if (pr.name.len > 0) c.setName(pr.name);
                const known = c.avatar_id;
                c.avatar_id = pr.avatar_id;
                if (self.ev.onProfile) |cb|
                    cb(self.ev.ctx, c, c.getName(), pr.avatar_id);
                if (self.sessions.get(contact_id)) |sess| {
                    const changed = !std.mem.eql(u8, &known, &pr.avatar_id);
                    if (changed and !std.mem.eql(u8, &pr.avatar_id, &@as([16]u8, @splat(0)))) {
                        sess.sendEnvelope(.{ .avatar_req = .{ .avatar_id = pr.avatar_id } }) catch {};
                    }
                }
            },
            .avatar => |av| {
                // контент-адресация: сверка id с хэшем данных
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(av.data, &digest, .{});
                if (!std.mem.eql(u8, digest[0..16], &av.avatar_id)) return; // битый id
                // дедуп по байтам — на уровне приложения (кэш avatars);
                // здесь всегда отдаём данные: PROFILE мог опередить байты
                c.avatar_id = av.avatar_id;
                if (self.ev.onAvatar) |cb| cb(self.ev.ctx, c, av.avatar_id, av.data);
                if (self.sessions.get(contact_id)) |sess| {
                    sess.sendEnvelope(.{ .avatar_ack = .{ .avatar_id = av.avatar_id } }) catch {};
                }
            },
            .avatar_ack => {},
            .avatar_req => |ar| {
                if (self.ev.onAvatarReq) |cb| cb(self.ev.ctx, c, ar.avatar_id);
            },
            .file_meta => |fm| {
                if (self.ev.onFileMeta) |cb| cb(self.ev.ctx, c, fm);
            },
            .file_data => |fd| {
                if (self.ev.onFileData) |cb| cb(self.ev.ctx, c, fd);
            },
            .file_ack => |fa| {
                // докачка: состояние отправителя ведёт сам движок
                self.fileAck(contact_id, fa);
            },
            .react => |r| {
                if (self.ev.onReaction) |cb| cb(self.ev.ctx, c, .{ .msg_id = r.msg_id, .op = r.op, .from = c.bundle, .code = r.code });
            },
            .block_notice => {
                if (self.ev.onBlockedNotice) |cb| cb(self.ev.ctx, c);
            },
            .presence_ping => |p| {
                const now = self.nowMs();
                self.markSeen(contact_id, now);
                if (self.sessions.get(contact_id)) |s| {
                    s.sendEnvelope(.{ .presence_pong = .{ .seq = p.seq, .ts_peer_ms = @intCast(now) } }) catch {};
                }
            },
            .presence_pong => {
                self.markSeen(contact_id, self.nowMs());
            },
            .call_signal => |cs| {
                if (self.ev.onCallSignal) |cb| cb(self.ev.ctx, c, cs.op, cs.call_id);
            },
            .call_audio => |ca| {
                if (self.ev.onCallAudio) |cb| cb(self.ev.ctx, c, ca.seq, ca.data);
            },
            // JOIN обрабатывается слоем приложения ДО dispatch (pending-сессии);
            // сюда попадает только повторный кадр на уже промоутнутой сессии
            .join => {},
        }
    }
};

fn filled32(v: u8) [32]u8 {
    const a: [32]u8 = @splat(v);
    return a;
}

const FileSentProbe = struct {
    fired: bool = false,
    size: u32 = 0,

    fn onFileSent(ctx: *anyopaque, _: *const Contact, _: [16]u8, size: u32, _: []const u8) void {
        const self: *FileSentProbe = @ptrCast(@alignCast(ctx));
        self.fired = true;
        self.size = size;
    }
};

test "engine: FileTx — постановка, позиция, откат, завершение" {
    const alloc = std.testing.allocator;
    const id = try identity_mod.Identity.fromSeed(filled32(3));
    const peer = try identity_mod.Identity.fromSeed(filled32(5));
    var probe = FileSentProbe{};
    var eng = Engine.init(alloc, std.testing.io, id, .{
        .ctx = &probe,
        .onFileSent = FileSentProbe.onFileSent,
    });
    defer eng.deinit();
    const idx = try eng.addContact("peer", peer.bundle());
    const cid: i64 = @intCast(idx + 1);

    // 100000 байт = 7 чанков; сессии нет -> queued, запись стоит
    const bytes: [100_000]u8 = @splat(0xAB);
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &sha, .{});
    const file_id = sha[0..16].*;
    const oc = try eng.sendFile(cid, file_id, "data.bin", &bytes, sha);
    try std.testing.expectEqual(Engine.SendResult.queued, oc.result);
    try std.testing.expectEqual(@as(usize, 1), eng.file_tx.items.len);
    try std.testing.expectEqual(@as(u32, 7), eng.file_tx.items[0].total);
    try std.testing.expect(eng.file_tx.items[0].await_pos);

    // идемпотентность по (cid, file_id): повтор не дублирует
    const oc2 = try eng.sendFile(cid, file_id, "data.bin", &bytes, sha);
    try std.testing.expectEqual(@as(usize, 1), eng.file_tx.items.len);
    try std.testing.expectEqual(Engine.SendResult.queued, oc2.result);

    // позиционный ACK (ответ на META): next_seq на позицию приёмника
    eng.dispatchEvent(cid, .{ .file_ack = .{ .file_id = file_id, .got = 5 } });
    const t = &eng.file_tx.items[0];
    try std.testing.expectEqual(@as(u32, 5), t.next_seq);
    try std.testing.expectEqual(@as(u32, 5), t.last_ack);
    try std.testing.expect(!t.await_pos);

    // прогресс-ACK: только вперёд, окно от last_ack (6 < total: живём)
    eng.dispatchEvent(cid, .{ .file_ack = .{ .file_id = file_id, .got = 6 } });
    try std.testing.expectEqual(@as(u32, 6), t.last_ack);
    try std.testing.expectEqual(@as(usize, 1), eng.file_tx.items.len);

    // завершение: got == total — запись гасится, onFileSent с размером
    eng.dispatchEvent(cid, .{ .file_ack = .{ .file_id = file_id, .got = 7 } });
    try std.testing.expectEqual(@as(usize, 0), eng.file_tx.items.len);
    try std.testing.expect(probe.fired);
    try std.testing.expectEqual(@as(u32, 100_000), probe.size);
}

test "engine: FileTx — сброс приёма (got < last_ack) с нуля" {
    const alloc = std.testing.allocator;
    const id = try identity_mod.Identity.fromSeed(filled32(11));
    const peer = try identity_mod.Identity.fromSeed(filled32(13));
    var probe = FileSentProbe{};
    var eng = Engine.init(alloc, std.testing.io, id, .{
        .ctx = &probe,
        .onFileSent = FileSentProbe.onFileSent,
    });
    defer eng.deinit();
    const idx = try eng.addContact("peer", peer.bundle());
    const cid: i64 = @intCast(idx + 1);

    const bytes: [40_000]u8 = @splat(0xCD); // 3 чанка
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &sha, .{});
    const file_id = sha[0..16].*;
    _ = try eng.sendFile(cid, file_id, "r.bin", &bytes, sha);

    // приёмник подтвердил 2, затем сбросился и сказал 0
    eng.dispatchEvent(cid, .{ .file_ack = .{ .file_id = file_id, .got = 2 } });
    eng.dispatchEvent(cid, .{ .file_ack = .{ .file_id = file_id, .got = 0 } });
    const t = &eng.file_tx.items[0];
    try std.testing.expectEqual(@as(u32, 0), t.next_seq);
    try std.testing.expectEqual(@as(u32, 0), t.last_ack);
    try std.testing.expect(!probe.fired);

    // чужой file_id игнорируется
    eng.dispatchEvent(cid, .{ .file_ack = .{ .file_id = @splat(9), .got = 1 } });
    try std.testing.expectEqual(@as(usize, 1), eng.file_tx.items.len);
}

test "engine block and react flow" {
    const alloc = std.testing.allocator;
    const id = try identity_mod.Identity.fromSeed(filled32(7));
    const peer = try identity_mod.Identity.fromSeed(filled32(9));
    var eng = Engine.init(alloc, std.testing.io, id, .{ .ctx = undefined });
    defer eng.deinit();
    const idx = try eng.addContact("peer", peer.bundle());
    const cid: i64 = @intCast(idx + 1);
    const oc = try eng.sendText(cid, "hi");
    try std.testing.expectEqual(Engine.SendResult.queued, oc.result);
    try eng.block(cid);
    try std.testing.expect(eng.contacts.items[idx].blocked);
    try eng.unblock(cid);
}
