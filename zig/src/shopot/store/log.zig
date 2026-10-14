//! Append-only шифрованный лог — замена SQLite для shopot-store.
//!
//! Формат файла (все целые — little-endian, никаких varint):
//!
//!     header (12B): [version u8 = 3][reserved u8 x3][epoch u32][base_seq u32]
//!     record:       [len u16][nonce 12B][box] (nonce = [0 x4][epoch][seq], детерминированный)
//!
//! `len` — длина данных после поля len (nonce + box), максимум 65535.
//! `box` — ChaCha20-Poly1305: ciphertext||tag(16B). AAD бокса — epoch u32 LE
//! файла, в котором запись живёт (защита от переноса записей между эпохами).
//! Открытый текст бокса: `[kind u8][seq u32][payload]`.
//!
//! Ключ шифрования — storage_key[32], выводится при open из seed вызывающего:
//! `storage_key = HKDF-SHA256-Expand(HKDF-SHA256-Extract("shopot-store-v3", seed), "", 32)`.
//! Ключ хранится в Log и обнуляется в deinit (std.crypto.secureZero).
//!
//! kind: msg=1, contact=2, block=3, react=4, set=5, tombstone=6.
//! Tombstone (payload = u32 LE — удаляемый seq) помечает запись в индексе
//! мёртвой; при компакции tombstone и dead-записи исчезают из нового файла.
//!
//! Любая структурная аномалия или сбой проверки подлинности бокса при чтении —
//! error.Corrupt: файлу ноль доверия.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;

const Allocator = mem.Allocator;

/// AEAD записей.
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
/// KDF для вывода storage key из seed.
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

/// Версия формата.
const version: u8 = 3;
/// Размер заголовка файла.
const header_size: u16 = 12;
/// Длина nonce ChaCha20-Poly1305.
const nonce_len: u16 = 12;
/// Длина тега Poly1305.
const tag_len: u16 = Aead.tag_length; // 16
/// Соль/контекст KDF.
const kdf_salt = "shopot-store-v3";
/// Размер открытого текста бокса без payload: kind u8 + seq u32.
const plain_hdr_len: u16 = 5;
/// Максимум payload одной записи: len(u16) покрывает nonce+открытый текст+tag.
pub const max_payload: usize = std.math.maxInt(u16) - nonce_len - plain_hdr_len - tag_len; // 65502
/// Максимальный размер одной записи на диске (вместе с полем len).
const max_record_disk: usize = 2 + nonce_len + plain_hdr_len + max_payload + tag_len; // 65537
/// Размер фиксированного буфера чтения.
const read_buf_size: usize = 64 * 1024;

comptime {
    std.debug.assert(max_record_disk <= @as(usize, std.math.maxInt(u16)) + 2);
    std.debug.assert(nonce_len == Aead.nonce_length);
    std.debug.assert(tag_len == Aead.tag_length);
}

/// Тип записи в логе.
pub const Kind = enum(u8) {
    /// Сообщение.
    msg = 1,
    /// Контакт.
    contact = 2,
    /// Заблокированный пользователь.
    block = 3,
    /// Реакция.
    react = 4,
    /// Настройка: [ключ u8][значение] (1 = мой avatar_id[16], 2 = моё имя).
    set = 5,
    /// Метка удаления (payload — u32 LE удаляемого seq).
    tombstone = 6,
    /// Outbox: 1 = [1][cid u16][msg_id 16][ts u64][len u16][body], 0 = [0][cid u16][msg_id 16].
    outbox = 7,
    /// Аватар: [avatar_id 16][len u16][data ≤ 16000] — кэш картинок.
    avatar = 8,
    /// Принятый файл: [cid u16][file_id 16][size u32][len u8][name].
    file = 9,
};

/// Единая ошибка модуля: файловые операции + память + семантика формата.
pub const Error = error{
    Corrupt,
    RecordTooLarge,
    SeqOverflow,
    EpochOverflow,
    EntropyUnavailable,
    AccessDenied,
    BadPathName,
    Canceled,
    DeviceBusy,
    DiskQuota,
    FileBusy,
    FileNotFound,
    FileTooBig,
    InputOutput,
    IsDir,
    NameTooLong,
    NetworkNotFound,
    NoDevice,
    NoSpaceLeft,
    NotDir,
    PathAlreadyExists,
    PermissionDenied,
    PipeBusy,
    ProcessFdQuotaExceeded,
    ReadOnlyFileSystem,
    FileLocksUnsupported,
    AntivirusInterference,
    SystemFdQuotaExceeded,
    SystemResources,
    SymLinkLoop,
    WouldBlock,
    Unexpected,
    OutOfMemory,
};

/// Порог размера файла по умолчанию для compactIfNeeded.
pub const default_max_bytes: u64 = 4 * 1024 * 1024;
/// Порог доли мусора по умолчанию для compactIfNeeded.
pub const default_dead_ratio: f64 = 0.5;

/// Запись индекса: метаданные одной записи файла.
pub const Entry = struct {
    /// Тип записи.
    kind: Kind,
    /// Монотонный номер записи.
    seq: u32,
    /// Смещение записи (её поля len) в файле.
    offset: u64,
    /// Помечена tombstone'ом как удалённая.
    dead: bool = false,
};

/// Append-only шифрованный лог.
pub const Log = struct {
    /// Аллокатор, удерживаемый для роста индекса (выдаётся в open).
    alloc: Allocator,
    /// Файловый дескриптор лога (блокирующий POSIX, без std.Io).
    fd: posix.fd_t,
    /// Путь файла (owned, zero-terminated — нужен для rename при компакции).
    path: [:0]u8,
    /// storage key; wipe в deinit.
    key: [32]u8,
    /// Сборочный буфер append (максимальная запись); wipe в deinit.
    scratch: []u8,
    /// Индекс всех записей файла, в порядке следования в файле.
    index: std.ArrayList(Entry),
    /// Эпоха файла (растёт на каждой компакции).
    epoch: u32,
    /// База нумерации seq из заголовка.
    base_seq: u32,
    /// seq следующей записи.
    next_seq: u32,
    /// Текущий размер файла в байтах.
    file_size: u64,

    /// Открывает (или создаёт) лог по пути `path`.
    ///
    /// Ключ выводится из `seed`; существующий файл читается целиком, каждый
    /// бокс верифицируется, строится индекс. Любая ошибка бокса/структуры —
    /// error.Corrupt (файлу ноль доверия, in-memory состояние не возвращается).
    /// Файл создаётся с правами 0600.
    pub fn open(gpa: Allocator, path: []const u8, seed: *const [32]u8) Error!Log {
        const fd = try posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDWR, .CREAT = true }, 0o600);
        errdefer _ = posix.system.close(fd);

        const path_z = try gpa.dupeSentinel(u8, path, 0);
        errdefer gpa.free(path_z);

        const scratch = try gpa.alloc(u8, max_record_disk);
        errdefer gpa.free(scratch);

        var index: std.ArrayList(Entry) = .empty;
        errdefer index.deinit(gpa);

        const key: [32]u8 = deriveKey(seed);

        // Буферы чтения: 64K фиксированный буфер файла + расшифрованный текст.
        var reader = Reader{
            .fd = fd,
            .buf = try gpa.alloc(u8, read_buf_size),
        };
        defer gpa.free(reader.buf);

        const pt = try gpa.alloc(u8, max_payload);
        defer {
            std.crypto.secureZero(u8, pt);
            gpa.free(pt);
        }

        var epoch: u32 = undefined;
        var base_seq: u32 = undefined;
        var next_seq: u32 = undefined;
        var file_size: u64 = undefined;

        if (!try reader.ensure(header_size)) {
            // Новый (или пустой) файл: пишем header эпохи 0.
            var hdr: [header_size]u8 = undefined;
            writeHeader(&hdr, 0, 0);
            try pwriteAll(fd, &hdr, 0);
            epoch = 0;
            base_seq = 0;
            next_seq = 0;
            file_size = header_size;
        } else {
            const h = reader.buf[reader.start..][0..header_size];
            if (h[0] != version) return error.Corrupt;
            epoch = mem.readInt(u32, h[4..8], .little);
            base_seq = mem.readInt(u32, h[8..12], .little);
            reader.start += header_size;

            var max_seq: ?u32 = null;
            while (true) {
                if (!try reader.ensure(2)) {
                    // EOF: чисто, если не осталось ни байта.
                    if (reader.start == reader.end) break;
                    return error.Corrupt; // мусорный хвост < 2 байт
                }
                const rec_offset = reader.base + reader.start;
                const len = mem.readInt(u16, reader.buf[reader.start..][0..2], .little);
                if (len < nonce_len + plain_hdr_len + tag_len) return error.Corrupt;
                if (!try reader.ensure(len)) return error.Corrupt; // запись оборвана
                const rec = reader.buf[reader.start + 2 ..][0..len];
                reader.start += 2 + @as(usize, len);

                const plain = try decryptRecord(rec, epoch, &key, pt);
                const parsed = try parsePlain(plain);
                try index.ensureUnusedCapacity(gpa, 1);
                index.appendAssumeCapacity(.{
                    .kind = parsed.kind,
                    .seq = parsed.seq,
                    .offset = rec_offset,
                });
                if (max_seq == null or parsed.seq > max_seq.?) max_seq = parsed.seq;
            }
            if (max_seq) |m| {
                if (m == std.math.maxInt(u32)) return error.SeqOverflow;
                next_seq = m + 1;
            } else {
                next_seq = base_seq;
            }
            file_size = reader.base + reader.end;
        }

        return .{
            .alloc = gpa,
            .fd = fd,
            .path = path_z,
            .key = key,
            .scratch = scratch,
            .index = index,
            .epoch = epoch,
            .base_seq = base_seq,
            .next_seq = next_seq,
            .file_size = file_size,
        };
    }

    /// Закрывает лог: обнуляет ключ и рабочие буферы, освобождает память.
    pub fn deinit(log: *Log) void {
        _ = posix.system.close(log.fd);
        std.crypto.secureZero(u8, &log.key);
        std.crypto.secureZero(u8, log.scratch);
        log.alloc.free(log.scratch);
        log.alloc.free(log.path);
        log.index.deinit(log.alloc);
        log.* = undefined;
    }

    /// Дописывает запись `kind` с `payload`; возвращает её seq.
    /// Ошибки: RecordTooLarge (payload > max_payload), SeqOverflow, файловые.
    /// fsync не выполняется (по контракту модуля).
    pub fn append(log: *Log, kind: Kind, payload: []const u8) Error!u32 {
        if (payload.len > max_payload) return error.RecordTooLarge;
        const seq = log.next_seq;
        if (seq == std.math.maxInt(u32)) return error.SeqOverflow;
        try log.index.ensureUnusedCapacity(log.alloc, 1);
        const rec = try assembleRecord(log.scratch, kind, seq, payload, log.epoch, &log.key);
        const offset = log.file_size;
        pwriteAll(log.fd, rec, offset) catch |err| {
            // Откат хвоста: в файле не должна остаться оборванная запись.
            _ = posix.system.ftruncate(log.fd, @intCast(offset));
            return err;
        };
        log.file_size += rec.len;
        log.next_seq = seq + 1;
        log.index.appendAssumeCapacity(.{
            .kind = kind,
            .seq = seq,
            .offset = offset,
        });
        return seq;
    }

    /// Дописывает tombstone на `target_seq` и помечает запись мёртвой в
    /// индексе; возвращает seq самого tombstone. Если записи с `target_seq`
    /// в индексе нет (например, она в прошлом файле), tombstone всё равно
    /// дописывается.
    pub fn appendTombstone(log: *Log, target_seq: u32) Error!u32 {
        var payload: [4]u8 = undefined;
        mem.writeInt(u32, &payload, target_seq, .little);
        const seq = try log.append(.tombstone, &payload);
        for (log.index.items) |*e| {
            if (e.seq == target_seq and !e.dead) {
                e.dead = true;
                break;
            }
        }
        return seq;
    }

    /// Читает все живые записи типа `kind`, возвращает их payload'ы.
    /// Каждый элемент и внешний срез выделяются из `gpa` — освобождает
    /// вызывающий: `for (items) |it| gpa.free(it); gpa.free(items);`.
    pub fn readAll(log: *const Log, kind: Kind, gpa: Allocator) Error![][]u8 {
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |item| gpa.free(item);
            out.deinit(gpa);
        }
        const rbuf = try gpa.alloc(u8, max_record_disk);
        defer gpa.free(rbuf);
        const pt = try gpa.alloc(u8, max_payload);
        defer {
            std.crypto.secureZero(u8, pt);
            gpa.free(pt);
        }
        for (log.index.items) |e| {
            if (e.dead or e.kind != kind) continue;
            const rec = try readRecordAt(log.fd, e.offset, rbuf);
            const plain = try decryptRecord(rec, log.epoch, &log.key, pt);
            const parsed = try parsePlain(plain);
            if (parsed.kind != e.kind or parsed.seq != e.seq) return error.Corrupt;
            try out.ensureUnusedCapacity(gpa, 1);
            out.appendAssumeCapacity(try gpa.dupe(u8, parsed.payload));
        }
        return out.toOwnedSlice(gpa);
    }

    /// Компакция, если нужна: файл больше `max_bytes` ИЛИ доля мусора
    /// (dead + tombstone) достигла `dead_ratio`.
    ///
    /// Живые записи перезаписываются в новый файл с epoch+1 (заново
    /// шифруются, порядок и seq сохраняются), файл синхронизируется и
    /// атомарно переименовывается поверх текущего пути лога; `path_new`
    /// используется как временное имя и после компакции не существует.
    /// Возвращает true, если компакция выполнена. Лог остаётся открытым
    /// и пригодным для append.
    pub fn compactIfNeeded(log: *Log, path_new: []const u8, max_bytes: u64, dead_ratio: f64) Error!bool {
        var removable: usize = 0;
        for (log.index.items) |e| {
            if (e.dead or e.kind == .tombstone) removable += 1;
        }
        const total = log.index.items.len;
        const ratio: f64 = if (total == 0)
            0
        else
            @as(f64, @floatFromInt(removable)) / @as(f64, @floatFromInt(total));
        if (log.file_size <= max_bytes and ratio < dead_ratio) return false;
        if (log.epoch == std.math.maxInt(u32)) return error.EpochOverflow;
        const new_epoch = log.epoch + 1;

        const nfd = try posix.openat(posix.AT.FDCWD, path_new, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
        }, 0o600);
        errdefer _ = posix.system.close(nfd);

        const pt = try log.alloc.alloc(u8, max_payload);
        defer {
            std.crypto.secureZero(u8, pt);
            log.alloc.free(pt);
        }
        const enc = try log.alloc.alloc(u8, max_record_disk);
        defer {
            std.crypto.secureZero(u8, enc);
            log.alloc.free(enc);
        }
        const rbuf = try log.alloc.alloc(u8, max_record_disk);
        defer log.alloc.free(rbuf);

        // Temp-файл не должен остаться при ошибке посреди компакции.
        errdefer {
            if (posix.toPosixPath(path_new)) |z| {
                _ = posix.system.unlinkat(posix.AT.FDCWD, &z, 0);
            } else |_| {}
        }

        var hdr: [header_size]u8 = undefined;
        writeHeader(&hdr, new_epoch, log.base_seq);
        try pwriteAll(nfd, &hdr, 0);
        var new_off: u64 = header_size;

        for (log.index.items) |*e| {
            if (e.dead or e.kind == .tombstone) continue;
            const old_rec = try readRecordAt(log.fd, e.offset, rbuf);
            const plain = try decryptRecord(old_rec, log.epoch, &log.key, pt);
            const parsed = try parsePlain(plain);
            if (parsed.kind != e.kind or parsed.seq != e.seq) return error.Corrupt;
            const new_rec = try assembleRecord(enc, e.kind, e.seq, parsed.payload, new_epoch, &log.key);
            try pwriteAll(nfd, new_rec, new_off);
            e.offset = new_off;
            new_off += new_rec.len;
        }

        try fsyncFd(nfd);

        const new_z = try posix.toPosixPath(path_new);
        const rc = posix.system.rename(&new_z, log.path.ptr);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .NOENT => return error.FileNotFound,
            .ACCES, .PERM => return error.AccessDenied,
            .IO => return error.InputOutput,
            .NOTDIR => return error.NotDir,
            .ISDIR => return error.IsDir,
            .BUSY => return error.DeviceBusy,
            .LOOP => return error.SymLinkLoop,
            .NAMETOOLONG => return error.NameTooLong,
            .NOSPC => return error.NoSpaceLeft,
            .NOMEM => return error.SystemResources,
            // EINTR у rename: атомарность не гарантирована — сообщаем об ошибке.
            .INTR => return error.Unexpected,
            else => return error.Unexpected,
        }

        const opened = try posix.openat(posix.AT.FDCWD, log.path, .{ .ACCMODE = .RDWR }, 0);
        _ = posix.system.close(log.fd);
        log.fd = opened;
        _ = posix.system.close(nfd);

        log.epoch = new_epoch;
        log.file_size = new_off;
        var w: usize = 0;
        for (log.index.items) |e| {
            if (!e.dead and e.kind != .tombstone) {
                log.index.items[w] = e;
                w += 1;
            }
        }
        log.index.shrinkRetainingCapacity(w);
        return true;
    }

    /// Текущий размер файла в байтах.
    pub fn size(log: *const Log) u64 {
        return log.file_size;
    }

    /// Число записей в индексе (включая tombstone и помеченные dead).
    pub fn recordCount(log: *const Log) usize {
        return log.index.items.len;
    }
};

/// Буферизованное последовательное чтение файла через фиксированный буфер.
const Reader = struct {
    fd: posix.fd_t,
    buf: []u8,
    /// Начало незаглощённых данных в buf.
    start: usize = 0,
    /// Конец валидных данных в buf.
    end: usize = 0,
    /// Абсолютное смещение файла, соответствующее buf[0].
    base: u64 = 0,

    /// Гарантирует `n` байт незаглощённых данных (n <= buf.len).
    /// Возвращает false, только если достигнут EOF и данных меньше n.
    fn ensure(self: *Reader, n: usize) Error!bool {
        std.debug.assert(n <= self.buf.len);
        if (self.end - self.start >= n) return true;
        const avail = self.end - self.start;
        if (self.start > 0) {
            mem.copyForwards(u8, self.buf[0..avail], self.buf[self.start..self.end]);
            self.base += self.start;
            self.start = 0;
            self.end = avail;
        }
        while (self.end < n) {
            const got = try preadAll(self.fd, self.buf[self.end..], self.base + self.end);
            if (got == 0) return false; // EOF
            self.end += got;
        }
        return true;
    }
};

/// Выводит storage key из seed: Extract(salt="shopot-store-v3"), Expand("").
fn deriveKey(seed: *const [32]u8) [32]u8 {
    var prk: [Hkdf.prk_length]u8 = Hkdf.extract(kdf_salt, seed);
    defer std.crypto.secureZero(u8, &prk);
    var key: [32]u8 = undefined;
    Hkdf.expand(&key, "", prk);
    return key;
}

/// Пишет заголовок файла.
fn writeHeader(buf: *[header_size]u8, epoch: u32, base_seq: u32) void {
    buf[0] = version;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    mem.writeInt(u32, buf[4..8], epoch, .little);
    mem.writeInt(u32, buf[8..12], base_seq, .little);
}

/// Заполняет buf криптостойкой энтропией ОС (getrandom).
/// Собирает зашифрованную запись в buf (buf.len >= max_record_disk).
fn assembleRecord(buf: []u8, kind: Kind, seq: u32, payload: []const u8, epoch: u32, key: *const [32]u8) Error![]u8 {
    if (payload.len > max_payload) return error.RecordTooLarge;
    const p: u16 = @intCast(payload.len);
    const len: u16 = nonce_len + plain_hdr_len + p + tag_len;
    var aad: [4]u8 = undefined;
    mem.writeInt(u32, &aad, epoch, .little);

    mem.writeInt(u16, buf[0..2], len, .little);
    // nonce детерминированный: [0 x4][epoch u32 LE][seq u32 LE]. Уникален в
    // рамках (storage_key, epoch, seq): seq монотонен внутри эпохи — повтора
    // пары (key, nonce) не бывает. Поле nonce на диске сохранено: старые записи
    // со случайным nonce читаются как раньше.
    @memset(buf[2..6], 0);
    mem.writeInt(u32, buf[6..10], epoch, .little);
    mem.writeInt(u32, buf[10..14], seq, .little);
    // Открытый текст: [kind u8][seq u32][payload]; шифруется на месте.
    buf[14] = @backingInt(kind);
    mem.writeInt(u32, buf[15..19], seq, .little);
    @memcpy(buf[19..][0..payload.len], payload);
    Aead.encrypt(
        buf[14..][0 .. plain_hdr_len + p],
        buf[19 + payload.len ..][0..tag_len],
        buf[14..][0 .. plain_hdr_len + p],
        aad[0..],
        buf[2..14][0..12].*,
        key.*,
    );
    return buf[0 .. 35 + p];
}

/// Расшифровывает и верифицирует запись; возвращает срез открытого текста
/// внутри pt. Любой сбой — error.Corrupt.
fn decryptRecord(rec: []const u8, epoch: u32, key: *const [32]u8, pt: []u8) Error![]u8 {
    if (rec.len < nonce_len + plain_hdr_len + tag_len) return error.Corrupt;
    const ct_len = rec.len - nonce_len - tag_len;
    var aad: [4]u8 = undefined;
    mem.writeInt(u32, &aad, epoch, .little);
    Aead.decrypt(
        pt[0..ct_len],
        rec[nonce_len..][0..ct_len],
        rec[nonce_len + ct_len ..][0..tag_len].*,
        aad[0..],
        rec[0..nonce_len][0..12].*,
        key.*,
    ) catch return error.Corrupt;
    return pt[0..ct_len];
}

/// Валидирует тег kind; null для неизвестного значения.
fn kindFromInt(raw: u8) ?Kind {
    inline for (@typeInfo(Kind).@"enum".field_values) |value| {
        if (value == raw) return @fromBackingInt(@intCast(raw));
    }
    return null;
}

/// Разбирает открытый текст бокса: [kind u8][seq u32][payload].
fn parsePlain(plain: []u8) Error!struct { kind: Kind, seq: u32, payload: []u8 } {
    if (plain.len < plain_hdr_len) return error.Corrupt;
    const kind = kindFromInt(plain[0]) orelse return error.Corrupt;
    const seq = mem.readInt(u32, plain[1..5], .little);
    // Tombstone несёт ровно u32.
    if (kind == .tombstone and plain.len != plain_hdr_len + 4) return error.Corrupt;
    return .{ .kind = kind, .seq = seq, .payload = plain[plain_hdr_len..] };
}

/// Читает запись (box целиком) по смещению; buf.len >= max_record_disk.
fn readRecordAt(fd: posix.fd_t, offset: u64, buf: []u8) Error![]u8 {
    var n = try preadAll(fd, buf[0..2], offset);
    if (n < 2) return error.Corrupt;
    const len = mem.readInt(u16, buf[0..2], .little);
    if (len < nonce_len + plain_hdr_len + tag_len) return error.Corrupt;
    n = try preadAll(fd, buf[2..][0..len], offset + 2);
    if (n < len) return error.Corrupt;
    return buf[2..][0..len];
}

/// pwrite-цикл: пишет buf целиком по смещению, переживает EINTR/частичную запись.
fn pwriteAll(fd: posix.fd_t, buf: []const u8, offset: u64) Error!void {
    var i: usize = 0;
    while (i < buf.len) {
        const rc = posix.system.pwrite(fd, buf.ptr + i, buf.len - i, @intCast(offset + i));
        switch (posix.errno(rc)) {
            .SUCCESS => i += @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .FBIG => return error.FileTooBig,
            .DQUOT => return error.DiskQuota,
            .BADF => return error.Unexpected,
            else => return error.Unexpected,
        }
    }
}

/// pread-цикл: читает до buf.len или EOF, возвращает число прочитанных байт.
fn preadAll(fd: posix.fd_t, buf: []u8, offset: u64) Error!usize {
    var i: usize = 0;
    while (i < buf.len) {
        const rc = posix.system.pread(fd, buf.ptr + i, buf.len - i, @intCast(offset + i));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) break;
                i += n;
            },
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .IO => return error.InputOutput,
            .BADF => return error.Unexpected,
            else => return error.Unexpected,
        }
    }
    return i;
}

/// fsync с повтором при EINTR.
fn fsyncFd(fd: posix.fd_t) Error!void {
    while (true) {
        const rc = posix.system.fsync(fd);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .DQUOT => return error.DiskQuota,
            else => return error.Unexpected,
        }
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Фиксированный тестовый seed.
const test_seed: [32]u8 = @splat(0xAB);

/// Уникальный путь временного файла теста.
fn tmpPath(alloc: Allocator, name: []const u8) Error![]u8 {
    return std.fmt.allocPrint(alloc, "/tmp/shopot-log-{s}-{d}.tmp", .{ name, std.Thread.getCurrentId() });
}

/// Удаляет временный файл, игнорируя ошибки.
fn rmFile(path: []const u8) void {
    const z = posix.toPosixPath(path) catch return;
    _ = posix.system.unlinkat(posix.AT.FDCWD, &z, 0);
}

/// Освобождает результат readAll.
fn freeRead(gpa: Allocator, items: [][]u8) void {
    for (items) |item| gpa.free(item);
    gpa.free(items);
}

test "новый файл: header создаётся сразу" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "header");
    defer alloc.free(path);
    defer rmFile(path);

    var log = try Log.open(alloc, path, &test_seed);
    defer log.deinit();
    try testing.expectEqual(@as(u64, header_size), log.size());
    try testing.expectEqual(@as(usize, 0), log.recordCount());

    // Файл на диске: версия 3, epoch 0, base_seq 0.
    const fd = try posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    defer _ = posix.system.close(fd);
    var buf: [header_size]u8 = undefined;
    try testing.expectEqual(@as(usize, header_size), try preadAll(fd, &buf, 0));
    try testing.expectEqual(version, buf[0]);
    try testing.expectEqual(@as(u32, 0), mem.readInt(u32, buf[4..8], .little));
    try testing.expectEqual(@as(u32, 0), mem.readInt(u32, buf[8..12], .little));
}

test "roundtrip: запись, закрытие, повторное открытие" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "roundtrip");
    defer alloc.free(path);
    defer rmFile(path);

    {
        var log = try Log.open(alloc, path, &test_seed);
        defer log.deinit();
        _ = try log.append(.msg, "привет");
        _ = try log.append(.contact, "bob");
    }

    var log = try Log.open(alloc, path, &test_seed);
    defer log.deinit();
    try testing.expectEqual(@as(usize, 2), log.recordCount());

    const msgs = try log.readAll(.msg, alloc);
    defer freeRead(alloc, msgs);
    try testing.expectEqual(@as(usize, 1), msgs.len);
    try testing.expectEqualStrings("привет", msgs[0]);

    const contacts = try log.readAll(.contact, alloc);
    defer freeRead(alloc, contacts);
    try testing.expectEqual(@as(usize, 1), contacts.len);
    try testing.expectEqualStrings("bob", contacts[0]);
}

test "kind-фильтрация" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "kinds");
    defer alloc.free(path);
    defer rmFile(path);

    var log = try Log.open(alloc, path, &test_seed);
    defer log.deinit();
    _ = try log.append(.msg, "m1");
    _ = try log.append(.contact, "c1");
    _ = try log.append(.msg, "m2");
    _ = try log.append(.react, "r1");
    _ = try log.append(.set, "s1");
    _ = try log.append(.block, "b1");

    const msgs = try log.readAll(.msg, alloc);
    defer freeRead(alloc, msgs);
    try testing.expectEqual(@as(usize, 2), msgs.len);
    try testing.expectEqualStrings("m1", msgs[0]);
    try testing.expectEqualStrings("m2", msgs[1]);

    const reacts = try log.readAll(.react, alloc);
    defer freeRead(alloc, reacts);
    try testing.expectEqual(@as(usize, 1), reacts.len);

    const blocks = try log.readAll(.block, alloc);
    defer freeRead(alloc, blocks);
    try testing.expectEqual(@as(usize, 1), blocks.len);
}

test "порядок seq: строгий рост и продолжение после reopen" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "seq");
    defer alloc.free(path);
    defer rmFile(path);

    var s1: u32 = undefined;
    var s2: u32 = undefined;
    {
        var log = try Log.open(alloc, path, &test_seed);
        defer log.deinit();
        s1 = try log.append(.msg, "a");
        s2 = try log.append(.msg, "b");
        _ = try log.append(.msg, "c");
        try testing.expect(s1 < s2);
    }
    var log = try Log.open(alloc, path, &test_seed);
    defer log.deinit();
    const s4 = try log.append(.msg, "d");
    try testing.expect(s4 > s2 + 1);
}

test "пустой payload" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "empty");
    defer alloc.free(path);
    defer rmFile(path);

    var log = try Log.open(alloc, path, &test_seed);
    defer log.deinit();
    _ = try log.append(.msg, "");
    const msgs = try log.readAll(.msg, alloc);
    defer freeRead(alloc, msgs);
    try testing.expectEqual(@as(usize, 1), msgs.len);
    try testing.expectEqual(@as(usize, 0), msgs[0].len);
}

test "payload больше max_payload -> RecordTooLarge" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "toolarge");
    defer alloc.free(path);
    defer rmFile(path);

    var log = try Log.open(alloc, path, &test_seed);
    defer log.deinit();
    const big = try alloc.alloc(u8, max_payload + 1);
    defer alloc.free(big);
    try testing.expectError(error.RecordTooLarge, log.append(.msg, big));
}

test "tamper байта бокса -> Corrupt" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "tamper-box");
    defer alloc.free(path);
    defer rmFile(path);

    var file_size: u64 = undefined;
    {
        var log = try Log.open(alloc, path, &test_seed);
        defer log.deinit();
        _ = try log.append(.msg, "один");
        _ = try log.append(.msg, "два");
        file_size = log.size();
    }

    // Портим последний байт файла (тег последнего бокса).
    try tamperByte(path, file_size - 1);
    try testing.expectError(error.Corrupt, Log.open(alloc, path, &test_seed));
}

test "tamper байта len -> Corrupt" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "tamper-len");
    defer alloc.free(path);
    defer rmFile(path);

    {
        var log = try Log.open(alloc, path, &test_seed);
        defer log.deinit();
        _ = try log.append(.msg, "один");
        _ = try log.append(.msg, "два");
    }
    // Портим поле len второй записи: 12 + 2 + len(первой записи).
    const fd = try posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDWR }, 0);
    defer _ = posix.system.close(fd);
    var two: [2]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), try preadAll(fd, &two, header_size));
    const rec1_len = mem.readInt(u16, &two, .little);
    try tamperByteAt(fd, header_size + 2 + @as(u64, rec1_len));

    try testing.expectError(error.Corrupt, Log.open(alloc, path, &test_seed));
}

test "tamper байта версии -> Corrupt" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "tamper-ver");
    defer alloc.free(path);
    defer rmFile(path);

    {
        var log = try Log.open(alloc, path, &test_seed);
        defer log.deinit();
        _ = try log.append(.msg, "x");
    }
    try tamperByte(path, 0);
    try testing.expectError(error.Corrupt, Log.open(alloc, path, &test_seed));
}

test "чужой seed -> Corrupt" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "wrong-seed");
    defer alloc.free(path);
    defer rmFile(path);

    {
        var log = try Log.open(alloc, path, &test_seed);
        defer log.deinit();
        _ = try log.append(.msg, "секрет");
    }
    var other: [32]u8 = test_seed;
    other[0] ^= 0xFF;
    try testing.expectError(error.Corrupt, Log.open(alloc, path, &other));
}

test "tombstone + compact: после компакции только живое" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "compact");
    defer alloc.free(path);
    defer rmFile(path);
    const path_new = try tmpPath(alloc, "compact-new");
    defer alloc.free(path_new);
    defer rmFile(path_new);

    var seq_a: u32 = undefined;
    var seq_c: u32 = undefined;
    {
        var log = try Log.open(alloc, path, &test_seed);
        defer log.deinit();
        seq_a = try log.append(.msg, "aaa");
        const seq_b = try log.append(.msg, "bbb");
        seq_c = try log.append(.msg, "ccc");
        _ = try log.append(.contact, "carol");
        _ = try log.appendTombstone(seq_b);
        // max_bytes=0: форсируем компакцию независимо от размера файла.
        try testing.expect(try log.compactIfNeeded(path_new, 0, default_dead_ratio));
        // В памяти лога — только живые записи.
        try testing.expectEqual(@as(usize, 3), log.recordCount());
        // Лог продолжает работать на исходном пути.
        _ = try log.append(.msg, "ddd");
    }

    var log = try Log.open(alloc, path, &test_seed);
    defer log.deinit();
    try testing.expectEqual(@as(usize, 4), log.recordCount());

    const msgs = try log.readAll(.msg, alloc);
    defer freeRead(alloc, msgs);
    try testing.expectEqual(@as(usize, 3), msgs.len);
    try testing.expectEqualStrings("aaa", msgs[0]);
    try testing.expectEqualStrings("ccc", msgs[1]);
    try testing.expectEqualStrings("ddd", msgs[2]);

    // Порядок seq сохранён.
    try testing.expect(seq_a < seq_c);

    const contacts = try log.readAll(.contact, alloc);
    defer freeRead(alloc, contacts);
    try testing.expectEqual(@as(usize, 1), contacts.len);
    try testing.expectEqualStrings("carol", contacts[0]);

    // append после reopen продолжает нумерацию.
    const s = try log.append(.msg, "eee");
    try testing.expect(s > seq_c);
}

test "compact не нужен -> false, temp-файл не создаётся" {
    const alloc = testing.allocator;
    const path = try tmpPath(alloc, "no-compact");
    defer alloc.free(path);
    defer rmFile(path);
    const path_new = try tmpPath(alloc, "no-compact-new");
    defer alloc.free(path_new);
    defer rmFile(path_new);

    var log = try Log.open(alloc, path, &test_seed);
    defer log.deinit();
    _ = try log.append(.msg, "мало данных");
    try testing.expect(!try log.compactIfNeeded(path_new, default_max_bytes, default_dead_ratio));
    try testing.expect(!try fileExists(path_new));
}

/// Проверяет существование файла без создания.
fn fileExists(path: []const u8) Error!bool {
    const fd = posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    _ = posix.system.close(fd);
    return true;
}

/// Переворачивает байт файла по смещению (через отдельный fd).
fn tamperByte(path: []const u8, offset: u64) Error!void {
    const fd = try posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDWR }, 0);
    defer _ = posix.system.close(fd);
    try tamperByteAt(fd, offset);
}

/// Переворачивает байт в открытом файле по смещению.
fn tamperByteAt(fd: posix.fd_t, offset: u64) Error!void {
    var b: [1]u8 = undefined;
    const n = try preadAll(fd, &b, offset);
    if (n != 1) return error.Corrupt;
    b[0] ^= 0x01;
    try pwriteAll(fd, &b, offset);
}
