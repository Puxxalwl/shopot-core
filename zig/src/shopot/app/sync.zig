//! Синхронизация устройств (device_sync): репликация записей шифрованной
//! БД на другие устройства того же пользователя. Устройство-«близнец» —
//! контакт, чей bundle равен собственному (устройства делят один сид
//! личности); связывается обычным инвайт-кодом (ACCEPT_INVITE).
//!
//! Модель — как у outbox: запись попадает в ОГРАНИЧЕННУЮ очередь каждого
//! устройства и ждёт сессии с ним; при коннекте ядро отдаёт записи
//! партиями (envelope SYNC 0x45), получатель применяет их к своей БД и
//! подтверждает (SYNC_ACK 0x46). Обрыв сессии до ACK возвращает партию в
//! голову очереди; повторная доставка безопасна — приём идемпотентен.
//!
//! Аутентификация: каждая запись MAC-ается HMAC-SHA256 над ключом
//! sync_key = HKDF(seed, "shopot-device-sync-v1") — отдельным от ключа
//! хранилища. Его может вычислить только устройство с тем же сидом:
//! чужой контакт, переславший подделанный SYNC, отбрасывается по MAC.
//!
//! Перевод адресации: записи лога адресуют контакты локальным cid; на
//! провод SYNC cid заменяется на bundle (64 байта) через переводчик,
//! внедряемый приложением, получатель отображает bundle в свой cid.
//! Записи больше max_rec не синхронизируются (например, аватары 16 КБ).
//!
//! Очередь ограничена (queue_cap записей / queue_bytes байтов на
//! устройство): старое вытесняется — как outbox. Память inflight-партий
//! тоже ограничена тем же queue_cap.
const std = @import("std");
const envelope = @import("../proto/envelope.zig");

/// HMAC-SHA256.
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
/// HKDF для вывода sync-ключа из сида.
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
/// Домен вывода ключа (отличен от «shopot-store-v3» хранилища).
const kdf_salt = "shopot-device-sync-v1";

/// Семантика записи SYNC (собственное пространство значений; 1-4
/// совпадают с видами лога для читаемости).
pub const RecKind = enum(u8) {
    /// Сообщение: [bundle 64][запись лога msg без cid].
    msg = 1,
    /// Контакт: запись лога contact как есть (bundle-ключуемая).
    contact = 2,
    /// Блокировка: запись лога block как есть ([bundle 64][flag u8]).
    block = 3,
    /// Реакция: [bundle 64][запись лога react без cid].
    react = 4,
    /// ACK доставки: [msg_id 16] (глобально уникален).
    ack = 5,
    /// Принятый файл: [bundle 64][запись лога file без cid].
    file = 6,
    /// Клиентская запись БД: [tag u8][ts u64][len u16][data] как в логе.
    client = 7,
    /// Конфигурация: blob формата app/config.zig.
    cfg = 8,
};

/// Максимум payload записи при постановке в очередь: после перевода
/// cid → bundle запись растёт на 62 байта и обязана влезть в лимит
/// конверта max_sync_rec_data.
pub const max_rec: usize = envelope.max_sync_rec_data - 64 + 2;
/// Капа очереди одного устройства (записи), как outbox.
pub const queue_cap: usize = 512;
/// Капа очереди одного устройства (байты payload).
pub const queue_bytes: usize = 2 * 1024 * 1024;

/// Длина MAC записи.
pub const mac_len = 32;

/// Ключ синхронизации из сида личности (отдельный домен HKDF).
pub fn deriveKey(seed: *const [32]u8) [32]u8 {
    var prk: [Hkdf.prk_length]u8 = Hkdf.extract(kdf_salt, seed);
    defer std.crypto.secureZero(u8, &prk);
    var key: [32]u8 = undefined;
    Hkdf.expand(&key, "sync", prk);
    return key;
}

/// MAC записи: HMAC-SHA256(sync_key, kind || payload). payload —
/// ПЕРЕВЕДЁННАЯ запись (то, что уйдёт на провод / хранится для client).
pub fn recordMac(key: *const [32]u8, kind: u8, payload: []const u8) [mac_len]u8 {
    var msg: [1 + 1]u8 = undefined; // hdr для HMAC с двумя «блобами»
    msg[0] = kind;
    var mac1: [mac_len]u8 = undefined;
    Hmac.create(&mac1, &msg, key);
    // двуступенчатый HMAC (kind, потом payload) эквивалентен MAC над
    // конкатенацией: домены развязаны длиной блоба первой ступени
    var mac: [mac_len]u8 = undefined;
    Hmac.create(&mac, payload, &mac1);
    return mac;
}

/// Запись в очереди устройства (payload — формат лога, cid ещё локальный).
pub const Rec = struct {
    kind: u8,
    payload: []u8,
};

/// Партия в полёте: отправлена, ждёт SYNC_ACK.
const Inflight = struct {
    batch_id: u32,
    /// Записи партии (owned); возвращаются в очередь при обрыве.
    recs: []Rec,
};

/// Очередь одного устройства.
pub const Device = struct {
    cid: i64,
    q: std.ArrayListUnmanaged(Rec) = .empty,
    /// Суммарные байты payload очереди.
    q_bytes: usize = 0,
    inflight: std.ArrayListUnmanaged(Inflight) = .empty,
    /// Счётчик записей в полёте (лимит — queue_cap).
    inflight_count: usize = 0,
    next_batch_id: u32 = 1,
};

/// Готовая партия (tail указывает в буфер вызывающего).
pub const Batch = struct {
    batch_id: u32,
    count: u8,
    tail: []const u8,
};

/// Координатор синхронизации: очередь на каждое связанное устройство.
pub const Sync = struct {
    alloc: std.mem.Allocator,
    /// Ключ синхронизации; обнуляется в deinit.
    key: [32]u8,
    /// Устройства: cid -> очередь.
    devices: std.AutoHashMapUnmanaged(i64, *Device) = .empty,
    /// Переводчик cid → bundle (инжектируется приложением: контакты).
    /// null-ответ = контакт исчез, запись отбрасывается.
    tr_ctx: ?*anyopaque = null,
    tr_fn: ?*const fn (ctx: ?*anyopaque, cid: i64) ?[64]u8 = null,

    /// Инициализация по сиду личности.
    pub fn init(alloc: std.mem.Allocator, seed: *const [32]u8) Sync {
        return .{ .alloc = alloc, .key = deriveKey(seed) };
    }

    /// Освободить всё (очереди, inflight) и обнулить ключ.
    pub fn deinit(self: *Sync) void {
        var it = self.devices.valueIterator();
        while (it.next()) |d| self.destroyDevice(d.*);
        self.devices.deinit(self.alloc);
        std.crypto.secureZero(u8, &self.key);
    }

    /// Зарегистрировать устройство (линк установлен). Идемпотентно.
    pub fn addDevice(self: *Sync, cid: i64) void {
        if (self.devices.contains(cid)) return;
        const d = self.alloc.create(Device) catch return;
        d.* = .{ .cid = cid };
        self.devices.put(self.alloc, cid, d) catch {
            self.alloc.destroy(d);
        };
    }

    /// Снять устройство (линк удалён): очереди выбрасываются.
    pub fn removeDevice(self: *Sync, cid: i64) void {
        const d = self.devices.get(cid) orelse return;
        _ = self.devices.remove(cid);
        self.destroyDevice(d);
    }

    pub fn hasDevice(self: *const Sync, cid: i64) bool {
        return self.devices.contains(cid);
    }

    fn destroyDevice(self: *Sync, d: *Device) void {
        for (d.q.items) |r| self.alloc.free(r.payload);
        d.q.deinit(self.alloc);
        for (d.inflight.items) |b| {
            for (b.recs) |r| self.alloc.free(r.payload);
            self.alloc.free(b.recs);
        }
        d.inflight.deinit(self.alloc);
        self.alloc.destroy(d);
    }

    /// Поставить запись во все очереди устройств (payload — формат лога,
    /// ≤ max_rec). Копия на каждое устройство; капы вытесняют старое.
    pub fn enqueue(self: *Sync, kind: u8, payload: []const u8) void {
        if (self.devices.count() == 0) return;
        if (payload.len == 0 or payload.len > max_rec) return;
        var it = self.devices.valueIterator();
        while (it.next()) |dp| {
            const d = dp.*;
            const copy = self.alloc.dupe(u8, payload) catch return;
            d.q.append(self.alloc, .{ .kind = kind, .payload = copy }) catch {
                self.alloc.free(copy);
                continue;
            };
            d.q_bytes += payload.len;
            // вытеснение с хвоста (самое старое): записи — конечный ресурс
            while (d.q.items.len > queue_cap or
                (d.q_bytes > queue_bytes and d.q.items.len > 1))
            {
                const old = d.q.orderedRemove(0);
                d.q_bytes -= old.payload.len;
                self.alloc.free(old.payload);
            }
        }
    }

    /// Есть ли очередь с ожидающими записями.
    pub fn hasPending(self: *const Sync) bool {
        var it = self.devices.valueIterator();
        while (it.next()) |d| {
            if (d.*.q.items.len > 0) return true;
        }
        return false;
    }

    /// Взять партию из головы очереди устройства: перевести cid → bundle,
    /// собрать tail в buf, ПЕРЕНЕСТИ записи в inflight. null — очередь
    /// пуста или inflight полон. Записи с исчезнувшим контактом
    /// отбрасываются.
    pub fn takeBatch(self: *Sync, d: *Device, buf: []u8) ?Batch {
        if (d.q.items.len == 0) return null;
        if (d.inflight_count >= queue_cap) return null;
        var pos: usize = 0;
        var n_rec: usize = 0;
        var recs: std.ArrayListUnmanaged(Rec) = .empty;
        defer recs.deinit(self.alloc);
        // scratch перевода: [bundle 64][payload без cid] ≤ 64 + max_rec
        var scratch: [64 + max_rec]u8 = undefined;
        while (d.q.items.len > 0 and n_rec < envelope.max_sync_recs) {
            // peek: перевод и влезание — ДО изъятия из очереди
            const head = d.q.items[0];
            const data = self.translate(head.kind, head.payload, &scratch) orelse {
                // контакт исчез: запись не переводится — выбросить
                const dead = d.q.orderedRemove(0);
                d.q_bytes -= dead.payload.len;
                self.alloc.free(dead.payload);
                continue;
            };
            if (pos + 1 + mac_len + 2 + data.len > buf.len) break;
            // запись уходит из очереди
            const rec = d.q.orderedRemove(0);
            d.q_bytes -= rec.payload.len;
            // wire: [kind u8][mac 32][len u16][data]
            buf[pos] = rec.kind;
            pos += 1;
            const mac = recordMac(&self.key, rec.kind, data);
            @memcpy(buf[pos..][0..mac_len], &mac);
            pos += mac_len;
            std.mem.writeInt(u16, buf[pos..][0..2], @intCast(data.len), .little);
            pos += 2;
            @memcpy(buf[pos..][0..data.len], data);
            pos += data.len;
            n_rec += 1;
            recs.append(self.alloc, rec) catch {
                self.alloc.free(rec.payload);
                break;
            };
            if (d.inflight_count + n_rec >= queue_cap) break;
        }
        if (n_rec == 0) return null;
        const slice = recs.toOwnedSlice(self.alloc) catch {
            for (recs.items) |r| self.alloc.free(r.payload);
            return null;
        };
        const batch_id = d.next_batch_id;
        d.next_batch_id +%= 1; // u32 wrap безопасен: id уникальны в рамках жизни очереди
        d.inflight.append(self.alloc, .{ .batch_id = batch_id, .recs = slice }) catch {
            for (slice) |r| self.alloc.free(r.payload);
            self.alloc.free(slice);
            return null;
        };
        d.inflight_count += n_rec;
        return .{ .batch_id = batch_id, .count = @intCast(n_rec), .tail = buf[0..pos] };
    }

    /// Перевод записи формата лога в формат провода SYNC. Возвращает срез
    /// (payload как есть или scratch для переведённых); null — контакт
    /// исчез, запись отбрасывается.
    fn translate(self: *Sync, kind: u8, payload: []const u8, scratch: []u8) ?[]const u8 {
        switch (kind) {
            @backingInt(RecKind.msg),
            @backingInt(RecKind.react),
            @backingInt(RecKind.file),
            => {
                if (payload.len < 2) return null;
                const cid: i64 = @intCast(std.mem.readInt(u16, payload[0..2], .little));
                const tr = self.tr_fn orelse return null;
                const bundle = tr(self.tr_ctx, cid) orelse return null;
                // [bundle 64][payload без cid u16]
                if (scratch.len < 64 + payload.len - 2) return null;
                @memcpy(scratch[0..64], &bundle);
                @memcpy(scratch[64..][0 .. payload.len - 2], payload[2..]);
                return scratch[0 .. 64 + payload.len - 2];
            },
            @backingInt(RecKind.ack) => {
                // [op u8][cid u16][msg_id 16] → [msg_id 16]
                if (payload.len < 3 + 16) return null;
                return payload[3..];
            },
            else => return payload,
        }
    }

    /// Партия подтверждена (SYNC_ACK): записи освобождаются.
    /// Неизвестный batch_id (после возврата в очередь) — игнор.
    pub fn onAck(self: *Sync, cid: i64, batch_id: u32) void {
        const d = self.devices.get(cid) orelse return;
        var i: usize = 0;
        while (i < d.inflight.items.len) : (i += 1) {
            if (d.inflight.items[i].batch_id == batch_id) {
                const b = d.inflight.orderedRemove(i);
                for (b.recs) |r| self.alloc.free(r.payload);
                d.inflight_count -= b.recs.len;
                self.alloc.free(b.recs);
                return;
            }
        }
    }

    /// Сессия с устройством умерла: все неподтверждённые партии — в голову
    /// очереди (в порядке отправки); повторная доставка идемпотентна.
    pub fn onSessionDown(self: *Sync, cid: i64) void {
        const d = self.devices.get(cid) orelse return;
        if (d.inflight.items.len == 0) return;
        // новая очередь: inflight-записи (по порядку партий) + остаток;
        // не влезающее в капу освобождается (записи — конечный ресурс)
        var merged: std.ArrayListUnmanaged(Rec) = .empty;
        var bytes: usize = 0;
        for (d.inflight.items) |b| {
            for (b.recs) |r| {
                if (merged.items.len >= queue_cap) {
                    self.alloc.free(r.payload);
                    continue;
                }
                merged.append(self.alloc, r) catch {
                    self.alloc.free(r.payload);
                    continue;
                };
                bytes += r.payload.len;
            }
            self.alloc.free(b.recs);
        }
        for (d.q.items) |r| {
            if (merged.items.len >= queue_cap) {
                self.alloc.free(r.payload);
                continue;
            }
            merged.append(self.alloc, r) catch {
                self.alloc.free(r.payload);
                continue;
            };
            bytes += r.payload.len;
        }
        // inflight сверх капы уже освобождены выше (free в циклах)
        var rest = d.q;
        d.q = merged;
        d.q_bytes = bytes;
        rest.clearAndFree(self.alloc);
        d.inflight.clearRetainingCapacity();
        d.inflight_count = 0;
    }

    /// Проверить MAC записи (формат лога уже переведён: data — как на проводе).
    pub fn verifyRec(self: *const Sync, kind: u8, mac: *const [mac_len]u8, data: []const u8) bool {
        if (data.len > envelope.max_sync_rec_data) return false;
        const want = recordMac(&self.key, kind, data);
        return std.mem.eql(u8, &want, mac);
    }
};

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_seed: [32]u8 = @splat(0x5A);

/// Переводчик-заглушка: cid 1 → фикс-бандл, прочее → null.
fn testTr(_: ?*anyopaque, cid: i64) ?[64]u8 {
    if (cid != 1) return null;
    return @splat(0xEE);
}

fn syncedHarness() Sync {
    var s = Sync.init(testing.allocator, &test_seed);
    s.tr_fn = testTr;
    return s;
}

test "deriveKey: отдельный домен (не ключ хранилища)" {
    const k1 = deriveKey(&test_seed);
    // другой домен хранилища
    var prk: [Hkdf.prk_length]u8 = Hkdf.extract("shopot-store-v3", &test_seed);
    defer std.crypto.secureZero(u8, &prk);
    var store_key: [32]u8 = undefined;
    Hkdf.expand(&store_key, "", prk);
    try testing.expect(!std.mem.eql(u8, &k1, &store_key));
    // другой сид — другой ключ
    var seed2: [32]u8 = test_seed;
    seed2[0] ^= 1;
    try testing.expect(!std.mem.eql(u8, &k1, &deriveKey(&seed2)));
}

test "recordMac: детерминизм и чувствительность" {
    const k = deriveKey(&test_seed);
    const m1 = recordMac(&k, 1, "запись");
    try testing.expectEqualSlices(u8, &m1, &recordMac(&k, 1, "запись"));
    try testing.expect(!std.mem.eql(u8, &m1, &recordMac(&k, 2, "запись")));
    try testing.expect(!std.mem.eql(u8, &m1, &recordMac(&k, 1, "запись2")));
    var k2 = k;
    k2[0] ^= 1;
    try testing.expect(!std.mem.eql(u8, &m1, &recordMac(&k2, 1, "запись")));
}

test "enqueue: копия каждому устройству, вытеснение по капе" {
    var s = syncedHarness();
    defer s.deinit();
    s.addDevice(7);
    s.addDevice(8);
    var big: [max_rec]u8 = undefined;
    @memset(&big, 1);
    // 600 записей > queue_cap=512: у каждого устройства остаётся 512
    var i: usize = 0;
    while (i < 600) : (i += 1) {
        s.enqueue(1, &big);
    }
    const d7 = s.devices.get(7).?;
    const d8 = s.devices.get(8).?;
    try testing.expectEqual(queue_cap, d7.q.items.len);
    try testing.expectEqual(queue_cap, d8.q.items.len);
    try testing.expectEqual(@as(usize, queue_cap * max_rec), d7.q_bytes);
    // слишком большая запись игнорируется
    var huge: [max_rec + 1]u8 = undefined;
    s.enqueue(1, &huge);
    try testing.expectEqual(queue_cap, d7.q.items.len);
}

test "takeBatch: перевод cid→bundle, mac, inflight, onAck" {
    var s = syncedHarness();
    defer s.deinit();
    s.addDevice(7);
    // запись msg формата лога: [cid u16=1][flags][msg_id 16][ts 8][len 2][body]
    var rec: [2 + 1 + 16 + 8 + 2 + 3]u8 = @splat(0);
    std.mem.writeInt(u16, rec[0..2], 1, .little);
    rec[2] = 0; // flags
    rec[3] = 0x42;
    std.mem.writeInt(u16, rec[27..29], 3, .little);
    rec[29] = 'a';
    rec[30] = 'b';
    rec[31] = 'c';
    s.enqueue(1, &rec);
    // запись с несуществующим cid: перевод невозможен — будет отброшена
    var bad: [3]u8 = @splat(0);
    std.mem.writeInt(u16, bad[0..2], 99, .little);
    s.enqueue(1, &bad);

    var buf: [envelope.max_sync_tail]u8 = undefined;
    const d = s.devices.get(7).?;
    const b = s.takeBatch(d, &buf);
    try testing.expect(b != null);
    const batch = b.?;
    try testing.expectEqual(@as(u8, 1), batch.count);
    // переведённая запись: [bundle 64][flags][msg_id][ts][len][body]
    try testing.expectEqual(@as(usize, 1 + mac_len + 2 + 64 + rec.len - 2), batch.tail.len);
    try testing.expectEqualSlices(u8, &@as([64]u8, @splat(0xEE)), batch.tail[1 + mac_len + 2 ..][0..64]);
    // структура tail валидна для конверта
    var views: [envelope.max_sync_recs]envelope.SyncRecView = undefined;
    try testing.expectEqual(@as(usize, 1), try envelope.parseSyncRecs(batch.tail, 1, &views));
    // MAC сходится
    try testing.expect(s.verifyRec(views[0].kind, &views[0].mac, views[0].data));
    // запись ушла в inflight, очередь пуста
    try testing.expectEqual(@as(usize, 0), d.q.items.len);
    try testing.expectEqual(@as(usize, 1), d.inflight.items.len);
    try testing.expectEqual(@as(usize, 1), d.inflight_count);
    // пустая очередь → null
    try testing.expect(s.takeBatch(d, &buf) == null);
    // ACK: inflight гасится
    s.onAck(7, batch.batch_id);
    try testing.expectEqual(@as(usize, 0), d.inflight.items.len);
    try testing.expectEqual(@as(usize, 0), d.inflight_count);
    // повторный ACK — игнор
    s.onAck(7, batch.batch_id);
}

test "takeBatch: запись без перевода (contact/cfg/client) идёт как есть" {
    var s = syncedHarness();
    defer s.deinit();
    s.addDevice(7);
    s.enqueue(8, "cfg-blob"); // RecKind.cfg — без перевода
    var buf: [envelope.max_sync_tail]u8 = undefined;
    const d = s.devices.get(7).?;
    const b = s.takeBatch(d, &buf).?;
    var views: [envelope.max_sync_recs]envelope.SyncRecView = undefined;
    _ = try envelope.parseSyncRecs(b.tail, b.count, &views);
    try testing.expectEqual(@as(u8, 8), views[0].kind);
    try testing.expectEqualStrings("cfg-blob", views[0].data);
    try testing.expect(s.verifyRec(8, &views[0].mac, views[0].data));
}

test "onSessionDown: inflight возвращается в голову очереди" {
    var s = syncedHarness();
    defer s.deinit();
    s.addDevice(7);
    s.enqueue(2, "первый");
    s.enqueue(2, "второй");
    var buf: [envelope.max_sync_tail]u8 = undefined;
    const d = s.devices.get(7).?;
    const b1 = s.takeBatch(d, &buf).?;
    s.enqueue(2, "третий"); // появился ПОСЛЕ отправки партии
    s.onSessionDown(7);
    // порядок: первый, второй (вернулись) — потом третий
    try testing.expectEqual(@as(usize, 3), d.q.items.len);
    try testing.expectEqualStrings("первый", d.q.items[0].payload);
    try testing.expectEqualStrings("второй", d.q.items[1].payload);
    try testing.expectEqualStrings("третий", d.q.items[2].payload);
    try testing.expectEqual(@as(usize, 0), d.inflight_count);
    _ = b1;
}

test "verifyRec: подделка отбрасывается" {
    var s = syncedHarness();
    defer s.deinit();
    var mac = recordMac(&s.key, 1, "data");
    mac[0] ^= 1;
    try testing.expect(!s.verifyRec(1, &mac, "data"));
    // чужой сид — чужой ключ: валидный MAC не принимается
    var seed2: [32]u8 = test_seed;
    seed2[1] ^= 1;
    var s3 = Sync.init(testing.allocator, &seed2);
    defer s3.deinit();
    const good = recordMac(&s.key, 1, "data");
    try testing.expect(!s3.verifyRec(1, &good, "data"));
}

test "removeDevice: память очереди освобождается" {
    var s = syncedHarness();
    defer s.deinit();
    s.addDevice(7);
    s.enqueue(2, "x");
    s.removeDevice(7);
    try testing.expect(!s.hasDevice(7));
    try testing.expectEqual(@as(usize, 0), s.devices.count());
}
