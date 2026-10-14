//! Fake-TLS транспортная маскировка: оборачивает любой Conn в поток,
//! неотличимый для пассивного DPI от TLS 1.3 (провода:
//! fake ClientHello/ServerHello + ChangeCipherSpec + fake Finished,
//! далее — записи application_data [17 03 03 len u16]).
//!
//! ЗАЧЕМ: протокол shopot на проводе имеет узнаваемую структуру
//! (кадры obf-классов 128..16384, публичные m1/m2/m3). Классифицирующий
//! DPI видит "неизвестный протокол" и может резать его. После обёртки
//! наблюдатель видит обычный TLS: рукопожатие + шифрованные записи.
//!
//! ЧЕСТНАЯ ГРАНИЦА: это маскировка, а не TLS. Активный MITM, который
//! терминирует настоящий TLS, увидит подделку (наш ClientHello не
//! содержит валидной криптографии ключей). От пассивного DPI
//! (классификация по отпечатку: размеры записей, JA3-like заголовки)
//! защищает. SNI выбирается случайно из списка невинных доменов.
//! Реальный обход IP-whitelist требует релея (см. docs/ROADMAP.md).
//!
//! Порядок байтов: заголовок записи — big-endian, как в настоящем TLS
//! (это часть маскировки). Внутренние слои (obf, конверты) — LE, как весь
//! проект.
const std = @import("std");
const interfaces = @import("../core/interfaces.zig");

pub const Error = interfaces.ConnError;

/// Роль: dialer = client (первым шлёт ClientHello), acceptor = server.
pub const Role = enum { client, server };

/// Тип записи TLS.
const rec_handshake: u8 = 0x16;
const rec_ccs: u8 = 0x14;
const rec_data: u8 = 0x17;

const tls_version = [3]u8{ 0x03, 0x03, 0x01 }; // legacy_version в ClientHello
/// Максимум данных в одной записи TLS.
const record_max: usize = 16384;
/// Длина fake Finished записи сервера (после CCS).
const fake_fin_len: usize = 40;

/// "Невинные" SNI для ClientHello: крупный CDN/хостинг, ничем не примечательны.
const sni_list = [_][]const u8{
    "www.cloudflare.com",
    "ajax.googleapis.com",
    "cdn.jsdelivr.net",
    "fonts.gstatic.com",
    "www.microsoft.com",
    "download.windowsupdate.com",
};

/// Построить fake ClientHello (запись 0x16) в buf. Возвращает срез записи.
fn clientHello(buf: []u8, io: std.Io) []const u8 {
    var n: usize = 0;
    var rnd: [64]u8 = undefined;
    io.random(&rnd);
    const sni = sni_list[std.mem.readInt(u64, rnd[56..64], .little) % sni_list.len];

    // запись: [тип][03 01][len u16 BE]
    buf[0] = rec_handshake;
    buf[1] = 0x03;
    buf[2] = 0x01;
    n = 5;
    const body_start = n;
    // handshake: [01][len u24 BE]
    buf[n] = 0x01;
    buf[n + 1] = 0x00;
    buf[n + 2] = 0x00;
    buf[n + 3] = 0x00; // len заполним в конце
    n += 4;
    const hs_start = n;
    // legacy_version + random32
    buf[n] = 0x03;
    buf[n + 1] = 0x03;
    n += 2;
    @memcpy(buf[n..][0..32], rnd[0..32]);
    n += 32;
    // session_id: 32 случайных байта (compat-стиль)
    buf[n] = 32;
    n += 1;
    @memcpy(buf[n..][0..32], rnd[32..64]);
    n += 32;
    // cipher_suites: TLS_AES_128_GCM_SHA256 + TLS_CHACHA20
    buf[n] = 0x00;
    buf[n + 1] = 0x04;
    buf[n + 2] = 0x13;
    buf[n + 3] = 0x01;
    buf[n + 4] = 0x13;
    buf[n + 5] = 0x03;
    n += 6;
    // compression: null
    buf[n] = 0x01;
    buf[n + 1] = 0x00;
    n += 2;
    // extensions (len u16 BE заполним в конце)
    const ext_start = n;
    n += 2;
    // server_name
    {
        buf[n] = 0x00;
        buf[n + 1] = 0x00; // type SNI
        n += 2;
        const sni_ext_len: u16 = @intCast(2 + 1 + 2 + sni.len);
        buf[n] = @intCast(sni_ext_len >> 8);
        buf[n + 1] = @truncate(sni_ext_len);
        n += 2;
        buf[n] = 0x00;
        n += 1; // list len hi
        buf[n] = @intCast((1 + 2 + sni.len) >> 8);
        n += 1;
        buf[n] = @truncate(1 + 2 + @as(u16, @intCast(sni.len)));
        n += 1;
        buf[n] = 0x00; // type host_name
        n += 1;
        buf[n] = @intCast(sni.len >> 8);
        n += 1;
        buf[n] = @truncate(sni.len);
        n += 1;
        @memcpy(buf[n..][0..sni.len], sni);
        n += sni.len;
    }
    // supported_versions: TLS 1.3
    {
        buf[n] = 0x00;
        buf[n + 1] = 0x2b;
        n += 2;
        buf[n] = 0x00;
        buf[n + 1] = 0x03;
        n += 2;
        buf[n] = 0x02;
        buf[n + 1] = 0x03;
        buf[n + 2] = 0x04;
        n += 3;
    }
    // ALPN: h2
    {
        buf[n] = 0x00;
        buf[n + 1] = 0x10;
        n += 2;
        buf[n] = 0x00;
        buf[n + 1] = 0x02;
        n += 2;
        buf[n] = 0x02;
        buf[n + 1] = 0x68;
        buf[n + 2] = 0x32; // "h2"
        n += 3;
    }
    // key_share x25519: 32 случайных байта (настоящих ключей нет — маскировка)
    {
        buf[n] = 0x00;
        buf[n + 1] = 0x33;
        n += 2;
        buf[n] = 0x00;
        buf[n + 1] = 0x26;
        n += 2;
        buf[n] = 0x00;
        buf[n + 1] = 0x24;
        n += 2;
        buf[n] = 0x00;
        buf[n + 1] = 0x1d; // x25519
        n += 2;
        @memcpy(buf[n..][0..32], rnd[0..32]);
        n += 32;
    }
    // размеры: extensions_len, hs_len, rec_len
    const ext_len = n - ext_start - 2;
    buf[ext_start] = @intCast(ext_len >> 8);
    buf[ext_start + 1] = @truncate(ext_len);
    const hs_len = n - hs_start;
    buf[body_start + 1] = @intCast(hs_len >> 16);
    buf[body_start + 2] = @intCast(hs_len >> 8);
    buf[body_start + 3] = @truncate(hs_len);
    const rec_len = n - body_start;
    buf[3] = @intCast(rec_len >> 8);
    buf[4] = @truncate(rec_len);
    return buf[0..n];
}

/// Построить ответ сервера: ServerHello + CCS + fake Finished (3 записи).
fn serverHello(buf: []u8, io: std.Io) []const u8 {
    var rnd: [48]u8 = undefined;
    io.random(&rnd);
    var n: usize = 0;
    // ServerHello
    buf[n] = rec_handshake;
    buf[n + 1] = 0x03;
    buf[n + 2] = 0x03;
    n += 5;
    const sh_start = n;
    buf[n] = 0x02; // server_hello
    buf[n + 1] = 0x00;
    buf[n + 2] = 0x00;
    buf[n + 3] = 0x00;
    n += 4;
    const hs_start = n;
    buf[n] = 0x03;
    buf[n + 1] = 0x03;
    n += 2;
    @memcpy(buf[n..][0..32], rnd[0..32]);
    n += 32;
    buf[n] = 32; // session_id echo
    n += 1;
    @memcpy(buf[n..][0..32], rnd[0..32]);
    n += 32;
    buf[n] = 0x13;
    buf[n + 1] = 0x01; // выбран AES-128-GCM
    n += 2;
    buf[n] = 0x00; // compression null
    n += 1;
    // extensions: supported_versions
    buf[n] = 0x00;
    buf[n + 1] = 0x2b;
    buf[n + 2] = 0x00;
    buf[n + 3] = 0x02;
    buf[n + 4] = 0x03;
    buf[n + 5] = 0x04;
    n += 6;
    const hs_len = n - hs_start;
    buf[sh_start + 1] = @intCast(hs_len >> 16);
    buf[sh_start + 2] = @intCast(hs_len >> 8);
    buf[sh_start + 3] = @truncate(hs_len);
    const rec1_len = n - sh_start;
    buf[sh_start - 2] = @intCast(rec1_len >> 8);
    buf[sh_start - 1] = @truncate(rec1_len);
    // ChangeCipherSpec
    buf[n] = rec_ccs;
    buf[n + 1] = 0x03;
    buf[n + 2] = 0x03;
    buf[n + 3] = 0x00;
    buf[n + 4] = 0x01;
    buf[n + 5] = 0x01;
    n += 6;
    // fake Finished: запись данных со случайным содержимым
    buf[n] = rec_data;
    buf[n + 1] = 0x03;
    buf[n + 2] = 0x03;
    buf[n + 3] = @intCast(fake_fin_len >> 8);
    buf[n + 4] = @truncate(fake_fin_len);
    n += 5;
    @memcpy(buf[n..][0..fake_fin_len], rnd[0..fake_fin_len]);
    n += fake_fin_len;
    return buf[0..n];
}

/// Обёртка Conn: TLS-подобный поток. Первый write отправляет fake-рукопожатие
/// (client: ClientHello; server: ServerHello+CCS+Finished), первый read
/// поглощает рукопожатие пира. Далее — записи application_data.
pub const FakeTlsConn = struct {
    inner: interfaces.Conn,
    alloc: std.mem.Allocator,
    io: std.Io,
    role: Role,
    hello_sent: bool = false,
    hello_read: bool = false,
    /// Буфер тела текущей записи (чтение).
    rbuf: []u8,
    rlen: usize = 0,
    rpos: usize = 0,

    const vtable = interfaces.Conn.VTable{
        .readAll = readAllImpl,
        .writeAll = writeAllImpl,
        .close = closeImpl,
    };

    /// Аллокация: rbuf на record_max. error.Closed — память.
    pub fn init(alloc: std.mem.Allocator, io: std.Io, inner: interfaces.Conn, role: Role) Error!FakeTlsConn {
        const rbuf = alloc.alloc(u8, record_max) catch return error.Closed;
        return .{ .inner = inner, .alloc = alloc, .io = io, .role = role, .rbuf = rbuf };
    }

    pub fn deinit(self: *FakeTlsConn) void {
        self.alloc.free(self.rbuf);
    }

    fn innerRead(self: *FakeTlsConn, out: []u8) Error!void {
        self.inner.readAll(out) catch |e| switch (e) {
            error.Closed => return error.Closed,
            error.Tampered => return error.Tampered,
            else => return error.Network,
        };
    }

    fn innerWrite(self: *FakeTlsConn, bytes: []const u8) Error!void {
        self.inner.writeAll(bytes) catch |e| switch (e) {
            error.Closed => return error.Closed,
            error.Tampered => return error.Tampered,
            else => return error.Network,
        };
    }

    /// Пропустить рукопожатие пира. Клиент: записи 0x16/0x14, затем ОДНА
    /// запись 0x17 (fake Finished, длина fake_fin_len). Сервер: одна 0x16.
    fn skipPeerHello(self: *FakeTlsConn) Error!void {
        var hdr: [5]u8 = undefined;
        switch (self.role) {
            .server => {
                try self.innerRead(&hdr);
                if (hdr[0] != rec_handshake) return error.Tampered;
                try self.skipBody(hdr);
            },
            .client => {
                while (true) {
                    try self.innerRead(&hdr);
                    if (hdr[0] == rec_data) {
                        // fake Finished сервера
                        const len = (@as(usize, hdr[3]) << 8) | hdr[4];
                        if (len != fake_fin_len) return error.Tampered;
                        try self.skipBody(hdr);
                        break;
                    }
                    if (hdr[0] != rec_handshake and hdr[0] != rec_ccs) return error.Tampered;
                    try self.skipBody(hdr);
                }
            },
        }
        self.hello_read = true;
    }

    fn skipBody(self: *FakeTlsConn, hdr: [5]u8) Error!void {
        const len = (@as(usize, hdr[3]) << 8) | hdr[4];
        var left = len;
        while (left > 0) {
            const n = @min(left, self.rbuf.len);
            try self.innerRead(self.rbuf[0..n]);
            left -= n;
        }
    }

    /// Читает ровно dest.len байт потока (тела записей 0x17).
    fn readAllImpl(ptr: *anyopaque, dest: []u8) Error!void {
        const self: *FakeTlsConn = @ptrCast(@alignCast(ptr));
        if (!self.hello_read) try self.skipPeerHello();
        var off: usize = 0;
        while (off < dest.len) {
            if (self.rpos >= self.rlen) {
                // следующая запись: [17 03 03 len u16 BE][тело]
                var hdr: [5]u8 = undefined;
                try self.innerRead(&hdr);
                if (hdr[0] != rec_data or hdr[1] != 0x03 or hdr[2] != 0x03) return error.Tampered;
                const len = (@as(usize, hdr[3]) << 8) | hdr[4];
                if (len == 0 or len > record_max) return error.Tampered;
                try self.innerRead(self.rbuf[0..len]);
                self.rlen = len;
                self.rpos = 0;
            }
            const avail = self.rlen - self.rpos;
            const n = @min(dest.len - off, avail);
            @memcpy(dest[off..][0..n], self.rbuf[self.rpos..][0..n]);
            self.rpos += n;
            off += n;
        }
    }

    /// Пишет буфер записями application_data по record_max.
    fn writeAllImpl(ptr: *anyopaque, buf: []const u8) Error!void {
        const self: *FakeTlsConn = @ptrCast(@alignCast(ptr));
        if (!self.hello_sent) {
            var hb: [512]u8 = undefined;
            const hello = switch (self.role) {
                .client => clientHello(&hb, self.io),
                .server => serverHello(&hb, self.io),
            };
            try self.innerWrite(hello);
            self.hello_sent = true;
        }
        var rest = buf;
        while (rest.len > 0) {
            const n = @min(rest.len, record_max);
            var hdr: [5]u8 = .{ rec_data, 0x03, 0x03, 0, 0 };
            hdr[3] = @intCast(n >> 8);
            hdr[4] = @truncate(n);
            try self.innerWrite(&hdr);
            try self.innerWrite(rest[0..n]);
            rest = rest[n..];
        }
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *FakeTlsConn = @ptrCast(@alignCast(ptr));
        // close_notify не нужен: TCP FIN после нашего close
        self.inner.close();
    }
};

/// Адаптер: обернуть conn в FakeTlsConn и отдать interfaces.Conn.
/// Владелец должен держать FakeTlsConn живым и вызвать deinit после close.
pub fn wrap(alloc: std.mem.Allocator, io: std.Io, inner: interfaces.Conn, role: Role) Error!struct { conn: interfaces.Conn, ftls: *FakeTlsConn } {
    const ftls = alloc.create(FakeTlsConn) catch return error.Closed;
    ftls.* = try FakeTlsConn.init(alloc, io, inner, role);
    return .{ .conn = .{ .ptr = ftls, .vtable = &FakeTlsConn.vtable }, .ftls = ftls };
}

// ==== Тесты ====
const testing = std.testing;

/// Двусторонняя труба в памяти: два буфера с семафором-очередью.
const Pipe = struct {
    a2b: std.ArrayListUnmanaged(u8) = .empty,
    b2a: std.ArrayListUnmanaged(u8) = .empty,
    alloc: std.mem.Allocator,
    // позиции чтения
    a_read: usize = 0,
    b_read: usize = 0,

    fn sideA(self: *Pipe) interfaces.Conn {
        return .{ .ptr = self, .vtable = &a_vt };
    }
    fn sideB(self: *Pipe) interfaces.Conn {
        return .{ .ptr = self, .vtable = &b_vt };
    }

    const a_vt = interfaces.Conn.VTable{
        .readAll = aRead,
        .writeAll = aWrite,
        .close = nopClose,
    };
    const b_vt = interfaces.Conn.VTable{
        .readAll = bRead,
        .writeAll = bWrite,
        .close = nopClose,
    };
    fn nopClose(_: *anyopaque) void {}

    fn aWrite(ptr: *anyopaque, buf: []const u8) Error!void {
        const self: *Pipe = @ptrCast(@alignCast(ptr));
        self.a2b.appendSlice(self.alloc, buf) catch return error.Closed;
    }
    fn bWrite(ptr: *anyopaque, buf: []const u8) Error!void {
        const self: *Pipe = @ptrCast(@alignCast(ptr));
        self.b2a.appendSlice(self.alloc, buf) catch return error.Closed;
    }
    fn aRead(ptr: *anyopaque, buf: []u8) Error!void {
        const self: *Pipe = @ptrCast(@alignCast(ptr));
        while (self.a_read >= self.b2a.items.len) return error.Closed; // в тесте данные уже записаны
        const n = @min(buf.len, self.b2a.items.len - self.a_read);
        @memcpy(buf[0..n], self.b2a.items[self.a_read..][0..n]);
        self.a_read += n;
        if (n < buf.len) return error.Closed;
    }
    fn bRead(ptr: *anyopaque, buf: []u8) Error!void {
        const self: *Pipe = @ptrCast(@alignCast(ptr));
        while (self.b_read >= self.a2b.items.len) return error.Closed;
        const n = @min(buf.len, self.a2b.items.len - self.b_read);
        @memcpy(buf[0..n], self.a2b.items[self.b_read..][0..n]);
        self.b_read += n;
        if (n < buf.len) return error.Closed;
    }
};

test "faketls: эхо клиент<->сервер, поток выглядит как TLS" {
    var pipe = Pipe{ .alloc = testing.allocator };
    defer {
        pipe.a2b.deinit(testing.allocator);
        pipe.b2a.deinit(testing.allocator);
    }
    const wa = try wrap(testing.allocator, testing.io, pipe.sideA(), .client);
    const wb = try wrap(testing.allocator, testing.io, pipe.sideB(), .server);
    defer {
        wa.ftls.deinit();
        testing.allocator.destroy(wa.ftls);
        wb.ftls.deinit();
        testing.allocator.destroy(wb.ftls);
    }
    const msg_a = "hello-from-client";
    const msg_b = "hello-from-server";
    try wa.conn.writeAll(msg_a);
    try wb.conn.writeAll(msg_b);
    var rbuf_a: [msg_b.len]u8 = undefined;
    var rbuf_b: [msg_a.len]u8 = undefined;
    try wb.conn.readAll(&rbuf_b);
    try testing.expectEqualStrings(msg_a, &rbuf_b);
    try wa.conn.readAll(&rbuf_a);
    try testing.expectEqualStrings(msg_b, &rbuf_a);
    // большой буфер через несколько записей
    var big: [40000]u8 = undefined;
    testing.io.random(&big);
    try wa.conn.writeAll(&big);
    var big2: [40000]u8 = undefined;
    try wb.conn.readAll(&big2);
    try testing.expectEqualSlices(u8, &big, &big2);
    // провод A->B: первая запись — ClientHello (0x16), данные — записи 0x17
    try testing.expect(pipe.a2b.items[0] == 0x16);
    try testing.expect(pipe.b2a.items[0] == 0x16); // ServerHello
    const after = pipe.a2b.items;
    var i: usize = 0;
    var saw_data = false;
    while (i + 5 <= after.len) {
        const len = (@as(usize, after[i + 3]) << 8) | after[i + 4];
        if (after[i] == rec_data) {
            saw_data = true;
            if (len == 0) return error.Tampered;
        }
        i += 5 + len;
    }
    try testing.expect(saw_data);
}
