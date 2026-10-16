//! Релей: само-хостнутый байтовый сплит для скрытия IP и обхода
//! IP-whitelist. Как MTProto-proxy по роли, но тупее: никакой крипты
//! (E2EE уже внутри shopot-сессии) — релей видит только TLS-подобный шум.
//!
//! Протокол (обе стороны — клиенты релея):
//!   клиент -> релей: [17 03 03 0030][marker 32 + шум 16] (TLS-подобная
//!                    запись AECD-правдоподобной длины: данные + «тег»)
//!   релей -> обоим:  [17 03 03 0012][5A + шум 17]        (спарен)
//!   далее: прозрачный сплит байтов (fake-TLS поток пира-а сквозной).
//! marker = HMAC-SHA256(секрет, "shopot-relay-v1"): вычисляют обе
//! стороны инвайта, релей видит только совпадение значений. Шум —
//! HMAC(marker, метка+наносекунды): выглядит случайно, уникален на
//! запись, без глобального состояния и без CSPRNG-syscall.
//!
//! Пары: первый коннект с marker-ом «владеет» слотом (presence), второй
//! спаривается, лишние коннекты при активной паре закрываются. После
//! обрыва пары слот ОСВОБОЖДАЕТСЯ: любая сторона может перерегистриро-
//! ваться и перекачать соединение без нового инвайта (докачка присутствия).
//! Два вида marker-а: одноразовый инвайт-секрет (invite_secret, фаза
//! знакомства) и ДОЛГОСРОЧНЫЙ контакт-секрет (identity.pairSecret ->
//! presenceMarker, фаза присутствия).
//! Режим демона: `shopot relay <host:port>` — никакого состояния shopot.
const std = @import("std");
const tcp = @import("tcp.zig");
const linux = std.os.linux;

pub const marker_len = 32;
/// Шум-хвост маркер-записи: запись выглядит как «32 байта + тег AECD».
pub const marker_noise_len = 16;
/// Сигнал «спарен» в теле TLS-подобной записи.
pub const pair_signal: u8 = 0x5A;
/// Шум-хвост сигнала: тело записи 1+17 = 18 байт (минимум AECD-записи).
pub const pair_noise_len = 17;
/// Метка домена релея в адресной части инвайта: @r/host:port.
pub const addr_mark = "r/";

/// Шум для хвостов relay-записей: HMAC-SHA256(marker, метка + наносекунды).
/// Не криптозащита (содержимое и так не секрет), а проводная маскировка:
/// байты неотличимы от случайных и не повторяются между записями.
fn noiseTail(marker: *const [marker_len]u8, out: []u8) void {
    // монотонные наносекунды прямым сисколлом (паттерн app/main.zig):
    // без глобального состояния, без аллокаций
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    const ns: u64 = @bitCast(@as(i64, ts.sec) *% std.time.ns_per_s +% ts.nsec);
    var inbuf: [21 + 8]u8 = undefined;
    @memcpy(inbuf[0..21], "shopot-relay-noise-v1");
    std.mem.writeInt(u64, inbuf[21..29], ns, .little);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &inbuf, marker);
    @memcpy(out, mac[0..out.len]);
}

/// marker из секрета инвайта (обе стороны вычисляют одинаково).
pub fn markerFrom(secret: [16]u8) [marker_len]u8 {
    var m: [marker_len]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&m, "shopot-relay-v1", &secret);
    return m;
}

/// Marker релей-присутствия: из ДОЛГОСРОЧНОГО парного секрета контакта
/// (identity.pairSecret — статик-статик X25519). Отличается доменом от
/// инвайт-marker-а: инвайт одноразовый, этот живёт столько, сколько
/// контакт.
pub fn presenceMarker(pair_secret: [32]u8) [marker_len]u8 {
    var m: [marker_len]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&m, "shopot-relay-presence-v1", &pair_secret);
    return m;
}

/// Клиент: подключиться к релею и зарегистрироваться marker-ом.
/// Возвращает готовый к сплиту коннект (после сигнала 0x5A).
pub fn dial(alloc: std.mem.Allocator, addr: []const u8, secret: [16]u8) !*tcp.TcpConn {
    return dialMarker(alloc, addr, markerFrom(secret));
}

/// То же с явным marker-ом (присутствие: контакт-секрет).
pub fn dialMarker(alloc: std.mem.Allocator, addr: []const u8, marker: [marker_len]u8) !*tcp.TcpConn {
    const tc = try tcp.dial(alloc, addr);
    errdefer {
        tc.deinit();
        alloc.destroy(tc);
    }
    // [17 03 03 0030][marker 32 + шум 16]: запись len=48 — AECD-подобно
    var w: [5 + marker_len + marker_noise_len]u8 = undefined;
    w[0] = 0x17;
    w[1] = 0x03;
    w[2] = 0x03;
    w[3] = 0;
    w[4] = marker_len + marker_noise_len;
    @memcpy(w[5..][0..marker_len], &marker);
    noiseTail(&marker, w[5 + marker_len ..][0..marker_noise_len]);
    try rawWriteAll(tc.fd, &w);
    // [17 03 03 0012][5A + шум 17]
    var r: [5 + 1 + pair_noise_len]u8 = undefined;
    try rawReadAll(tc.fd, &r);
    if (r[0] != 0x17 or r[1] != 0x03 or r[2] != 0x03 or r[3] != 0 or
        r[4] != 1 + pair_noise_len or r[5] != pair_signal)
        return error.NotRelay;
    return tc;
}

fn rawReadAll(fd: linux.socket_t, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        const rc = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (linux.errno(rc) != .SUCCESS) return error.Network;
        if (rc == 0) return error.Closed;
        got += @intCast(rc);
    }
}

fn rawWriteAll(fd: linux.socket_t, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(fd, bytes[sent..].ptr, bytes.len - sent);
        if (linux.errno(rc) != .SUCCESS) return error.Network;
        if (rc == 0) return error.Network;
        sent += @intCast(rc);
    }
}

/// Одна спаренная пара на релее.
const Pending = struct {
    fd: linux.socket_t,
    peer_fd: ?linux.socket_t = null,
    paired: bool = false,
};

/// Спин-лок (std.Thread.Mutex в этой версии std отсутствует; паттерн app).
const Spin = struct {
    v: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn lock(self: *Spin) void {
        while (self.v.swap(true, .acquire)) std.Thread.yield() catch {};
    }
    fn unlock(self: *Spin) void {
        self.v.store(false, .release);
    }
};

/// Частота проверки второго клиента. 1 мс уменьшает время спаривания
/// (обычно это один RTT), не влияя на пропускную способность уже спаренной пары.
const sleep1: linux.timespec = .{ .sec = 0, .nsec = 1 * std.time.ns_per_ms };

/// Сервер релея: цикл accept, спаривание, сплит. Блокирует навсегда;
/// stop (для тестов): флаг + закрытый слушатель выводят из цикла.
pub fn serve(alloc: std.mem.Allocator, listener: *tcp.Listener, stop: ?*std.atomic.Value(bool)) void {
    var map = std.AutoHashMap([marker_len]u8, *Pending).init(alloc);
    defer map.deinit();
    var spin = Spin{};

    while (true) {
        const tc = listener.accept(alloc) catch {
            if (stop) |st| {
                if (st.load(.seq_cst)) break;
            }
            continue;
        };
        // tc-структура не нужна потоку (он работает с fd): копия в аргументах
        const th = std.Thread.spawn(.{}, relayConn, .{ alloc, &map, &spin, tc.fd }) catch {
            _ = linux.close(tc.fd);
            alloc.destroy(tc);
            continue;
        };
        th.detach();
        alloc.destroy(tc);
    }
}

/// Поток одного коннекта релея: прочитать marker, спарить, копировать
/// свой -> пир. Обратное направление копирует пир-поток.
fn relayConn(alloc: std.mem.Allocator, map: *std.AutoHashMap([marker_len]u8, *Pending), spin: *Spin, fd: linux.socket_t) void {
    // [17 03 03 0030][marker 32 + шум 16]
    var hdr: [5]u8 = undefined;
    rawReadAll(fd, &hdr) catch return closeFd(fd);
    if (hdr[0] != 0x17 or hdr[1] != 0x03 or hdr[2] != 0x03 or
        hdr[4] != marker_len + marker_noise_len) return closeFd(fd);
    var body: [marker_len + marker_noise_len]u8 = undefined;
    rawReadAll(fd, &body) catch return closeFd(fd);
    const marker: [marker_len]u8 = body[0..marker_len].*;

    const self: *Pending = alloc.create(Pending) catch return closeFd(fd);
    self.* = .{ .fd = fd };

    var peer_fd: linux.socket_t = 0;
    var second: bool = false;
    var entry: *Pending = self; // валидно только для second
    {
        spin.lock();
        defer spin.unlock();
        if (map.get(marker)) |other| {
            if (other.paired) {
                // пара активна: слот занят, лишний коннект закрываем
                alloc.destroy(self);
                return closeFd(fd);
            }
            // второй клиент: спарить и оповестить первого; запись
            // ОСТАЁТСЯ в map на время пары (лишние коннекты — см. выше),
            // снятие регистрации и закрытие fd — обязанность second
            other.peer_fd = fd;
            other.paired = true;
            peer_fd = other.fd;
            second = true;
            entry = other;
        } else {
            // первый: зарегистрироваться и ждать пару (поллинг 50 мс)
            map.put(marker, self) catch {
                alloc.destroy(self);
                return closeFd(fd);
            };
            while (!self.paired) {
                spin.unlock();
                _ = linux.nanosleep(&sleep1, null);
                spin.lock();
                // счёт коннекта мог умереть? пира ждём до закрытия fd
            }
            peer_fd = self.peer_fd.?;
        }
    }
    // сигнал «спарен» обоим: [17 03 03 0012][5A + шум 17]
    if (second) {
        var sig: [5 + 1 + pair_noise_len]u8 = undefined;
        sig[0] = 0x17;
        sig[1] = 0x03;
        sig[2] = 0x03;
        sig[3] = 0;
        sig[4] = 1 + pair_noise_len;
        sig[5] = pair_signal;
        noiseTail(&marker, sig[6..][0..pair_noise_len]);
        rawWriteAll(fd, &sig) catch {};
        rawWriteAll(peer_fd, &sig) catch {};
    }
    // сплит: свой fd -> пир (обратное направление копирует пир-поток)
    splice(fd, peer_fd);
    if (second) {
        // пара закончилась: слот освободить, оба fd закрыть единожды
        // (first закрывать не должен — shutdown ниже будит его splice)
        spin.lock();
        if (map.get(marker)) |cur| {
            if (cur == entry) {
                _ = map.remove(marker);
                alloc.destroy(entry);
            }
        }
        spin.unlock();
        alloc.destroy(self); // свой Pending
        _ = linux.shutdown(fd, linux.SHUT.RDWR);
        _ = linux.shutdown(peer_fd, linux.SHUT.RDWR);
        closeFd(fd);
        closeFd(peer_fd);
    }
    // first: второй поток закрывает оба fd; выходим молча
}

fn closeFd(fd: linux.socket_t) void {
    _ = linux.close(fd);
}

/// Копирование fd -> peer_fd до обрыва. 64 KiB снижает число read/write
/// syscall на bulk transfer; память живёт только на стеке relay-потока.
fn splice(fd: linux.socket_t, peer_fd: linux.socket_t) void {
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(rc) != .SUCCESS) return;
        const n: usize = @intCast(rc);
        if (n == 0) return;
        rawWriteAll(peer_fd, buf[0..n]) catch return;
    }
}

// ==== Тесты ====
const testing = std.testing;

test "relay: marker детерминирован и зависит от секрета" {
    const a: [16]u8 = @splat(1);
    const m1 = markerFrom(a);
    const m2 = markerFrom(a);
    const c: [16]u8 = @splat(2);
    const m3 = markerFrom(c);
    try testing.expectEqualSlices(u8, &m1, &m2);
    try testing.expect(!std.mem.eql(u8, &m1, &m3));
    try testing.expect(m1[0] != 0 or m1[1] != 0); // не вырожден
}

test "relay: presenceMarker детерминирован и отделён доменом от инвайта" {
    const sec: [32]u8 = @splat(7);
    const p1 = presenceMarker(sec);
    const p2 = presenceMarker(sec);
    try testing.expectEqualSlices(u8, &p1, &p2);
    const other: [32]u8 = @splat(8);
    try testing.expect(!std.mem.eql(u8, &p1, &presenceMarker(other)));
    // домен отделён от инвайт-marker-а (те же байты секрета)
    const invite16: [16]u8 = @splat(7);
    try testing.expect(!std.mem.eql(u8, &p1, &markerFrom(invite16)));
}

test "relay: шум хвостов записей — не нулевой и уникальный на запись" {
    const m: [marker_len]u8 = @splat(5);
    var a: [marker_noise_len]u8 = undefined;
    var b: [pair_noise_len]u8 = undefined;
    noiseTail(&m, &a);
    // не вырожден
    try testing.expect(a[0] != 0 or a[1] != 0 or a[2] != 0);
    // время идёт — хвосты уникальны (до 64 попыток: наносекунды монотонны)
    var differs = false;
    for (0..64) |_| {
        noiseTail(&m, &b);
        if (!std.mem.eql(u8, &a, b[0..a.len])) {
            differs = true;
            break;
        }
    }
    try testing.expect(differs);
}
