//! Шифрованный поток поверх Conn (см. core/interfaces.zig).
//! Кадр на проводе: [u16 wirelen LE][nonce8][ChaCha20Poly1305 box(pad(payload))],
//! где nonce12 = [0,0,0,0] || nonce8. Полная длина кадра на проводе
//! (хедер + бокс) попадает в один из классов pad-таблицы — наблюдатель видит
//! только классы размеров. Ключ obf_key[32] ПЕРЕДАЁТ вызывающий (после
//! handshake: HKDF(transcript, "shopot-obf-v3")); здесь только симметрия.
//! Случайность (nonce, довесок паддинга) даёт вызывающий через std.Io —
//! так же, как heartbeat получает время, а Conn — транспорт.
const std = @import("std");
const interfaces = @import("../core/interfaces.zig");

pub const Error = error{
    /// Conn закрыт либо исчерпан аллокатор при инициализации.
    Closed,
    /// Тег AEAD не сошёлся либо структура кадра невалидна.
    Tampered,
    /// Полезная нагрузка не влезает в один кадр.
    TooLong,
};

const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

/// Классы размеров кадра на проводе. Совпадает с таблицей crypto/pad.zig.
/// ВНИМАНИЕ: импортировать crypto/pad.zig запрещено (чужой модуль), поэтому
/// таблица и padTo/unpad дублируются здесь ОСОЗНАННО. Формат провода общий:
/// при изменении таблицы в crypto/pad.zig синхронно менять здесь.
const buckets = [_]usize{ 128, 256, 512, 1024, 4096, 16384, 65536 };

const header_len = 2; // [u16 LE wirelen], формат длины как в net/framing.zig
const nonce_len = 8; // случайный префикс одноразового nonce
const tag_len = Aead.tag_length; // 16
/// Полный оверхед кадра: заголовок + nonce + тег AEAD.
const frame_overhead = header_len + nonce_len + tag_len; // 26
/// Трейлер паддинга: [u16 LE pad_len] — число байт случайного довеска.
const pad_meta_len = 2;

/// Максимальная полезная нагрузка одного кадра: кадр укладывается в класс
/// 16384 (16384 - 26 - 2). Валидно и для кадра любого большего класса.
pub const payload_chunk_max: usize = buckets[5] - frame_overhead - pad_meta_len; // 16356

/// true, если total_len — валидная полная длина кадра на проводе.
fn isBucketLen(total_len: usize) bool {
    for (buckets) |b| {
        if (b == total_len) return true;
    }
    return false;
}

/// Минимальный класс, вмещающий payload с оверхедом и меткой паддинга.
fn bucketFor(payload_len: usize) ?usize {
    for (buckets) |b| {
        if (b >= payload_len + frame_overhead + pad_meta_len) return b;
    }
    return null;
}

/// Паддит payload до ближайшего класса buckets:
/// payload || random || [u16 LE pad_len]; возвращает заполненный префикс
/// padded_buf, чья длина равна (класс - frame_overhead).
/// error.TooLong — payload не влезает ни в один класс.
fn padTo(padded_buf: []u8, payload: []const u8, io: std.Io) error{TooLong}![]u8 {
    const bucket = bucketFor(payload.len) orelse return error.TooLong;
    const padded_len = bucket - frame_overhead;
    if (padded_buf.len < padded_len) return error.TooLong;
    const padded = padded_buf[0..padded_len];
    const pad_len = padded_len - pad_meta_len - payload.len;
    @memcpy(padded[0..payload.len], payload);
    io.random(padded[payload.len..][0..pad_len]); // случайный довесок
    std.mem.writeInt(u16, padded[padded.len - pad_meta_len ..][0..pad_meta_len], @intCast(pad_len), .little);
    return padded;
}

/// Обратное padTo: восстанавливает payload из паддированного plaintext.
/// error.Tampered — длина не из класса buckets либо битая метка довеска.
fn unpad(padded: []const u8) error{Tampered}![]const u8 {
    if (padded.len < pad_meta_len + 1 or !isBucketLen(padded.len + frame_overhead)) return error.Tampered;
    const pad_len = std.mem.readInt(u16, padded[padded.len - pad_meta_len ..][0..pad_meta_len], .little);
    if (pad_len + pad_meta_len > padded.len) return error.Tampered; // pad_len == 0 допустим: payload занял весь класс
    return padded[0 .. padded.len - pad_meta_len - pad_len];
}

/// Шифрующий писатель: нарезает поток на кадры, шифрует и пишет в Conn.
pub const ObfWriter = struct {
    conn: interfaces.Conn,
    alloc: std.mem.Allocator,
    io: std.Io,
    key: [32]u8,
    /// Рабочий буфер без аллокаций на кадр: [wire: buckets[5]][plain: buckets[5]-26].
    scratch: []u8,

    const scratch_len = buckets[5] + (buckets[5] - frame_overhead);

    /// Создаёт писатель над conn. obf_key передаёт вызывающий, здесь хранится
    /// копия (обнуляется в deinit); io даёт CSPRNG для nonce и паддинга.
    /// Одна аллокация рабочего буфера — на кадр аллокаций нет.
    /// error.Closed — исчерпан аллокатор.
    pub fn init(alloc: std.mem.Allocator, io: std.Io, conn: interfaces.Conn, obf_key: *const [32]u8) Error!ObfWriter {
        const scratch = alloc.alloc(u8, scratch_len) catch return error.Closed;
        return .{ .conn = conn, .alloc = alloc, .io = io, .key = obf_key.*, .scratch = scratch };
    }

    /// Обнуляет остатки plaintext в рабочем буфере, освобождает его и ключ.
    pub fn deinit(self: *ObfWriter) void {
        std.crypto.secureZero(u8, self.scratch);
        self.alloc.free(self.scratch);
        std.crypto.secureZero(u8, &self.key);
        self.scratch = self.scratch[0..0];
    }

    /// Шифрует и пишет payload ОДНИМ кадром (<= payload_chunk_max).
    pub fn writeFrame(self: *ObfWriter, payload: []const u8) Error!void {
        if (payload.len > payload_chunk_max) return error.TooLong;
        const bucket = bucketFor(payload.len) orelse return error.TooLong;
        const padded = padTo(self.scratch[buckets[5]..], payload, self.io) catch return error.TooLong;

        const wire = self.scratch[0..bucket];
        const wire_len: u16 = @intCast(bucket - header_len);
        std.mem.writeInt(u16, wire[0..header_len], wire_len, .little);
        self.io.random(wire[header_len..][0..nonce_len]); // nonce8: случайный префикс nonce12
        var nonce12: [Aead.nonce_length]u8 = @splat(0);
        @memcpy(nonce12[Aead.nonce_length - nonce_len ..], wire[header_len..][0..nonce_len]);
        const ct = wire[frame_overhead - tag_len ..][0..padded.len];
        const tag = wire[frame_overhead - tag_len + padded.len ..][0..tag_len];
        // AAD = заголовок длины: бокс привязан к wirelen
        Aead.encrypt(ct, tag, padded, wire[0..header_len], nonce12, self.key);

        self.conn.writeAll(wire) catch |e| switch (e) {
            error.Closed => return error.Closed,
            error.Tampered => return error.Tampered,
            // WouldBlock/Network нарушают контракт Conn.writeAll ("всё или ошибка")
            else => return error.Closed,
        };
    }

    /// Шифрует и пишет plain, нарезая на кадры <= payload_chunk_max.
    /// Без аллокаций: plaintext ходит по предвыделенному scratch.
    pub fn writeAll(self: *ObfWriter, plain: []const u8) Error!void {
        var rest = plain;
        while (rest.len > 0) {
            const n = @min(rest.len, payload_chunk_max);
            try self.writeFrame(rest[0..n]);
            rest = rest[n..];
        }
    }
};

/// Расшифровывающий читатель: собирает payload из кадров Conn.
pub const ObfReader = struct {
    conn: interfaces.Conn,
    alloc: std.mem.Allocator,
    key: [32]u8,
    /// Рабочий буфер: [wire: buckets[6]][plain: buckets[6]-26]; plain хранит
    /// недочитанный остаток payload между вызовами readAll.
    scratch: []u8,
    /// Валидные байты остатка: scratch[wire_max..][0..leftover_len].
    leftover_len: usize = 0,
    leftover_pos: usize = 0,

    const wire_max = buckets[6]; // 65536: принимаем кадры всех классов таблицы
    const scratch_len = wire_max + (wire_max - frame_overhead);

    /// Создаёт читатель над conn. obf_key передаёт вызывающий, здесь хранится
    /// копия (обнуляется в deinit). error.Closed — исчерпан аллокатор.
    pub fn init(alloc: std.mem.Allocator, conn: interfaces.Conn, obf_key: *const [32]u8) Error!ObfReader {
        const scratch = alloc.alloc(u8, scratch_len) catch return error.Closed;
        return .{ .conn = conn, .alloc = alloc, .key = obf_key.*, .scratch = scratch };
    }

    /// Обнуляет и освобождает рабочий буфер и копию ключа.
    pub fn deinit(self: *ObfReader) void {
        std.crypto.secureZero(u8, self.scratch);
        self.alloc.free(self.scratch);
        std.crypto.secureZero(u8, &self.key);
        self.scratch = self.scratch[0..0];
    }

    /// Читает ровно dest.len байт payload, при необходимости из нескольких
    /// кадров (остаток предыдущего кадра отдаётся первым).
    pub fn readAll(self: *ObfReader, dest: []u8) Error!void {
        var off: usize = 0;
        while (off < dest.len) {
            if (self.leftover_pos < self.leftover_len) {
                const avail = self.leftover_len - self.leftover_pos;
                const n = @min(dest.len - off, avail);
                const src = self.scratch[wire_max..];
                @memcpy(dest[off..][0..n], src[self.leftover_pos..][0..n]);
                self.leftover_pos += n;
                off += n;
            } else {
                try self.readFrame();
            }
        }
    }

    fn readExact(self: *ObfReader, out: []u8) Error!void {
        self.conn.readAll(out) catch |e| switch (e) {
            error.Closed => return error.Closed,
            error.Tampered => return error.Tampered,
            // WouldBlock/Network нарушают контракт Conn.readAll ("ровно buf.len или Closed")
            else => return error.Closed,
        };
    }

    /// Читает и расшифровывает один кадр, кладёт payload в leftover.
    fn readFrame(self: *ObfReader) Error!void {
        self.leftover_len = 0;
        self.leftover_pos = 0;
        const wire = self.scratch[0..wire_max];
        var hdr: [header_len]u8 = undefined;
        try self.readExact(&hdr);
        const wire_len = std.mem.readInt(u16, &hdr, .little);
        const total = header_len + @as(usize, wire_len);
        if (!isBucketLen(total)) return error.Tampered; // поток не нашей разметки
        try self.readExact(wire[header_len..total]);

        const padded_len = total - frame_overhead;
        var nonce12: [Aead.nonce_length]u8 = @splat(0);
        @memcpy(nonce12[Aead.nonce_length - nonce_len ..], wire[header_len..][0..nonce_len]);
        const ct = wire[frame_overhead - tag_len ..][0..padded_len];
        const tag: [tag_len]u8 = wire[frame_overhead - tag_len + padded_len ..][0..tag_len].*;
        const plain = self.scratch[wire_max..][0..padded_len];
        // AAD = заголовок длины, как на стороне шифрования
        Aead.decrypt(plain, ct, tag, hdr[0..header_len], nonce12, self.key) catch return error.Tampered;
        const payload = unpad(plain) catch return error.Tampered;
        self.leftover_len = payload.len; // payload уже лежит в начале plain
    }
};

/// Пара ObfWriter + ObfReader над одним транспортом.
pub const ObfConn = struct {
    writer: ObfWriter,
    reader: ObfReader,

    const vtable = interfaces.Conn.VTable{
        .readAll = readAllImpl,
        .writeAll = writeAllImpl,
        .close = closeImpl,
    };

    /// Создаёт шифрованное соединение над conn с ключом вызывающего;
    /// io используется для nonce и паддинга.
    pub fn init(alloc: std.mem.Allocator, io: std.Io, conn: interfaces.Conn, obf_key: *const [32]u8) Error!ObfConn {
        var writer = try ObfWriter.init(alloc, io, conn, obf_key);
        errdefer writer.deinit();
        const reader = try ObfReader.init(alloc, conn, obf_key);
        return .{ .writer = writer, .reader = reader };
    }

    /// Обнуляет ключи и освобождает рабочие буферы. Сам conn не закрывает.
    pub fn deinit(self: *ObfConn) void {
        self.reader.deinit();
        self.writer.deinit();
    }

    fn readAllImpl(ptr: *anyopaque, buf: []u8) interfaces.ConnError!void {
        const self: *ObfConn = @ptrCast(@alignCast(ptr));
        return self.reader.readAll(buf) catch |e| switch (e) {
            error.Closed => error.Closed,
            error.Tampered => error.Tampered,
            error.TooLong => error.Network, // недостижимо: readAll собирает payload из кадров
        };
    }

    fn writeAllImpl(ptr: *anyopaque, buf: []const u8) interfaces.ConnError!void {
        const self: *ObfConn = @ptrCast(@alignCast(ptr));
        return self.writer.writeAll(buf) catch |e| switch (e) {
            error.Closed => error.Closed,
            error.Tampered => error.Tampered,
            error.TooLong => error.Network, // недостижимо: writeAll режет поток на кадры
        };
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *ObfConn = @ptrCast(@alignCast(ptr));
        self.writer.conn.close();
    }
};

/// Адаптер vtable для движка: obfConn(&obf_conn) -> interfaces.Conn.
pub fn obfConn(ptr: *ObfConn) interfaces.Conn {
    return .{ .ptr = ptr, .vtable = &ObfConn.vtable };
}

// ==== Тесты: фейковый транспорт на буферах ====

const testing = std.testing;

/// Однонаправленная очередь байтов (фейковая труба теста).
const Queue = struct {
    mem: []u8,
    len: usize = 0,

    fn write(self: *Queue, bytes: []const u8) bool {
        if (self.len + bytes.len > self.mem.len) return false;
        @memcpy(self.mem[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
        return true;
    }

    fn read(self: *Queue, out: []u8) bool {
        if (out.len > self.len) return false;
        @memcpy(out, self.mem[0..out.len]);
        std.mem.copyForwards(u8, self.mem[0 .. self.len - out.len], self.mem[out.len..self.len]);
        self.len -= out.len;
        return true;
    }
};

/// Фейковый Conn: readAll берёт из rx, writeAll кладёт в tx.
const PipeConn = struct {
    alloc: std.mem.Allocator,
    rx: *Queue,
    tx: *Queue,
    closed: bool = false,

    fn conn(self: *PipeConn) interfaces.Conn {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = interfaces.Conn.VTable{ .readAll = readAllImpl, .writeAll = writeAllImpl, .close = closeImpl };

    fn readAllImpl(ptr: *anyopaque, buf: []u8) interfaces.ConnError!void {
        const self: *PipeConn = @ptrCast(@alignCast(ptr));
        // однопоточный тест: недостача байт = конец потока
        if (!self.rx.read(buf)) return error.Closed;
    }

    fn writeAllImpl(ptr: *anyopaque, buf: []const u8) interfaces.ConnError!void {
        const self: *PipeConn = @ptrCast(@alignCast(ptr));
        if (!self.tx.write(buf)) return error.Closed;
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *PipeConn = @ptrCast(@alignCast(ptr));
        self.closed = true;
    }
};

/// Пара встречных PipeConn: a.tx == b.rx (a->b), b.tx == a.rx (b->a).
const PipePair = struct {
    alloc: std.mem.Allocator,
    q_ab: *Queue,
    q_ba: *Queue,
    a: PipeConn,
    b: PipeConn,

    fn create(alloc: std.mem.Allocator, cap: usize) !PipePair {
        const q_ab = try alloc.create(Queue);
        errdefer alloc.destroy(q_ab);
        const q_ba = try alloc.create(Queue);
        errdefer alloc.destroy(q_ba);
        q_ab.* = .{ .mem = try alloc.alloc(u8, cap) };
        errdefer alloc.free(q_ab.mem);
        q_ba.* = .{ .mem = try alloc.alloc(u8, cap) };
        errdefer alloc.free(q_ba.mem);
        return .{
            .alloc = alloc,
            .q_ab = q_ab,
            .q_ba = q_ba,
            .a = .{ .alloc = alloc, .rx = q_ba, .tx = q_ab },
            .b = .{ .alloc = alloc, .rx = q_ab, .tx = q_ba },
        };
    }

    fn destroy(self: *PipePair) void {
        self.alloc.free(self.q_ab.mem);
        self.alloc.free(self.q_ba.mem);
        self.alloc.destroy(self.q_ab);
        self.alloc.destroy(self.q_ba);
    }
};

fn testKey(byte: u8) [32]u8 {
    var key: [32]u8 = undefined;
    @memset(&key, byte);
    return key;
}

test "obf: padTo/unpad по классам buckets" {
    var buf: [buckets[6]]u8 = undefined;
    const p = try padTo(&buf, "hello", testing.io);
    try testing.expectEqual(buckets[0] - frame_overhead, p.len); // класс 128 -> 102
    try testing.expectEqualStrings("hello", try unpad(p));

    // пустой payload: ровно один класс, pad_len = весь довесок
    const p0 = try padTo(&buf, "", testing.io);
    try testing.expectEqual(buckets[0] - frame_overhead, p0.len);
    try testing.expectEqual(@as(usize, 0), (try unpad(p0)).len);

    // порча метки довеска -> Tampered
    p0[p0.len - 1] +%= 8;
    try testing.expectError(error.Tampered, unpad(p0));
    // слишком короткий вход -> Tampered
    try testing.expectError(error.Tampered, unpad("ab"));
    // payload больше максимального класса -> TooLong
    var big: [70_000]u8 = undefined;
    try testing.expectError(error.TooLong, padTo(&buf, &big, testing.io));
}

test "obf: roundtrip через пару ObfConn в памяти" {
    const alloc = testing.allocator;
    var pair = try PipePair.create(alloc, 1 << 17);
    defer pair.destroy();
    const key = testKey(0x42);
    var a = try ObfConn.init(alloc, testing.io, pair.a.conn(), &key);
    defer a.deinit();
    var b = try ObfConn.init(alloc, testing.io, pair.b.conn(), &key);
    defer b.deinit();

    var msg: [70_000]u8 = undefined; // >= 5 кадров
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i *% 2654435761 +% 11);
    try a.writer.writeAll(&msg);

    var got: [msg.len]u8 = undefined;
    try b.reader.readAll(&got);
    try testing.expectEqualSlices(u8, &msg, &got);

    // обратное направление
    try b.writer.writeAll("pong-back");
    var back: [9]u8 = undefined;
    try a.reader.readAll(&back);
    try testing.expectEqualStrings("pong-back", &back);

    // движок работает поверх адаптера interfaces.Conn
    var c = obfConn(&a);
    try c.writeAll("via-vtable");
    var vbuf: [10]u8 = undefined;
    try b.reader.readAll(&vbuf);
    try testing.expectEqualStrings("via-vtable", &vbuf);
    c.close();
    try testing.expect(pair.a.closed);
}

test "obf: короткие чтения и склейка кадров" {
    const alloc = testing.allocator;
    var pair = try PipePair.create(alloc, 4096);
    defer pair.destroy();
    const key = testKey(7);
    var w = try ObfWriter.init(alloc, testing.io, pair.a.conn(), &key);
    defer w.deinit();
    var r = try ObfReader.init(alloc, pair.b.conn(), &key);
    defer r.deinit();

    try w.writeAll("abcdef");
    var two: [2]u8 = undefined;
    try r.readAll(&two);
    try testing.expectEqualStrings("ab", &two);
    try r.readAll(&two);
    try testing.expectEqualStrings("cd", &two);
    try r.readAll(&two);
    try testing.expectEqualStrings("ef", &two);

    // чтение большее одного кадра собирает payload из двух кадров
    try w.writeAll("xy");
    try w.writeAll("zw");
    var four: [4]u8 = undefined;
    try r.readAll(&four);
    try testing.expectEqualStrings("xyzw", &four);

    // пустые операции
    var empty: [0]u8 = undefined;
    try w.writeAll(&empty);
    try r.readAll(&empty);
    try testing.expectEqual(@as(usize, 0), pair.q_ab.len);
}

test "obf: длины кадров на проводе попадают в классы buckets" {
    const alloc = testing.allocator;
    // границы каждого класса: вместимость класса = bucket - 26 - 2
    const sizes = [_]usize{ 1, 99, 100, 101, 227, 228, 229, 483, 484, 995, 996, 4067, 4068, 16355, 16356 };
    for (sizes) |sz| {
        var pair = try PipePair.create(alloc, 1 << 17);
        defer pair.destroy();
        const key = testKey(3);
        var w = try ObfWriter.init(alloc, testing.io, pair.a.conn(), &key);
        defer w.deinit();

        var payload: [16356]u8 = undefined;
        for (payload[0..sz], 0..) |*byte, i| byte.* = @truncate(i +% @as(usize, sz));
        try w.writeAll(payload[0..sz]);

        // разбор провода [u16 wirelen][nonce8][box]: полная длина (бокс+хидер)
        // обязана попасть в один из классов, ровно в ожидаемый
        const wire = pair.q_ab.mem[0..pair.q_ab.len];
        var off: usize = 0;
        var frames: usize = 0;
        while (off < wire.len) {
            const wire_len = std.mem.readInt(u16, wire[off..][0..2], .little);
            const total = header_len + @as(usize, wire_len);
            try testing.expect(isBucketLen(total));
            try testing.expectEqual(bucketFor(sz).?, total);
            off += total;
            frames += 1;
        }
        try testing.expectEqual(@as(usize, 1), frames);
    }

    // длинный поток нарезается на кадры одного старшего используемого класса
    var pair = try PipePair.create(alloc, 1 << 17);
    defer pair.destroy();
    const key = testKey(5);
    var w = try ObfWriter.init(alloc, testing.io, pair.a.conn(), &key);
    defer w.deinit();
    var long_msg: [40_000]u8 = undefined;
    @memset(&long_msg, 0x5A);
    try w.writeAll(&long_msg); // 16356 + 16356 + 7288 -> 3 кадра класса 16384
    const wire = pair.q_ab.mem[0..pair.q_ab.len];
    var off: usize = 0;
    var frames: usize = 0;
    while (off < wire.len) {
        const wire_len = std.mem.readInt(u16, wire[off..][0..2], .little);
        const total = header_len + @as(usize, wire_len);
        try testing.expect(isBucketLen(total));
        off += total;
        frames += 1;
    }
    try testing.expectEqual(@as(usize, 3), frames);
}

test "obf: tamper байта кадра -> Tampered" {
    const alloc = testing.allocator;
    // байты: 0..1 wirelen, 2..9 nonce, 10.. шифротекст, последний — тег
    const flips = [_]usize{ 15, 127, 0, 5 };
    for (flips) |flip| {
        var pair = try PipePair.create(alloc, 4096);
        defer pair.destroy();
        const key = testKey(0x42);
        var w = try ObfWriter.init(alloc, testing.io, pair.a.conn(), &key);
        defer w.deinit();
        var r = try ObfReader.init(alloc, pair.b.conn(), &key);
        defer r.deinit();

        try w.writeAll("secret");
        try testing.expectEqual(buckets[0], pair.q_ab.len); // кадр класса 128
        pair.q_ab.mem[flip] ^= 0xFF;
        var out: [6]u8 = undefined;
        try testing.expectError(error.Tampered, r.readAll(&out));
    }
}

test "obf: несовпадающий ключ -> Tampered" {
    const alloc = testing.allocator;
    var pair = try PipePair.create(alloc, 4096);
    defer pair.destroy();
    const k1 = testKey(1);
    const k2 = testKey(2);
    var w = try ObfWriter.init(alloc, testing.io, pair.a.conn(), &k1);
    defer w.deinit();
    var r = try ObfReader.init(alloc, pair.b.conn(), &k2);
    defer r.deinit();

    try w.writeAll("hi");
    var out: [2]u8 = undefined;
    try testing.expectError(error.Tampered, r.readAll(&out));
}

test "obf: writeFrame за пределами класса -> TooLong" {
    const alloc = testing.allocator;
    var pair = try PipePair.create(alloc, 1 << 17);
    defer pair.destroy();
    const key = testKey(9);
    var w = try ObfWriter.init(alloc, testing.io, pair.a.conn(), &key);
    defer w.deinit();

    var big: [payload_chunk_max + 1]u8 = undefined;
    @memset(&big, 1);
    try testing.expectError(error.TooLong, w.writeFrame(&big));
    try testing.expectEqual(@as(usize, 0), pair.q_ab.len);

    // ровно максимум — один кадр класса 16384
    try w.writeFrame(big[0..payload_chunk_max]);
    try testing.expectEqual(buckets[5], pair.q_ab.len);
}
