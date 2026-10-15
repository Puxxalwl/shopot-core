//! Fake-TLS транспортная маскировка v2: оборачивает любой Conn в поток,
//! неотличимый для пассивного DPI от Chrome ↔ TLS 1.3-сервер.
//!
//! ЗАЧЕМ: протокол shopot на проводе имеет узнаваемую структуру
//! (кадры obf-классов 128..16384, публичные m1/m2/m3). Классифицирующий
//! DPI видит «неизвестный протокол» и может резать его. После обёртки
//! наблюдатель видит обычный браузерный TLS.
//!
//! ЧТО НА ПРОВОДЕ (v2):
//!   client: ClientHello — байтовый шаблон реального Chrome 155 (16 шифров,
//!     19 расширений, GREASE, key_share X25519MLKEM768+x25519, ECH-grease,
//!     trust anchors, ALPS), с пер-соединительной рандомизацией random/
//!     session_id/GREASE-поинтов/кейшеров/SNI/порядка расширений
//!     (перестановка как у BoringSSL/Chrome). Затем CCS (compat-режим) и
//!     запись Finished (52 = 36+16) — побайтово направление client→server
//!     совпадает с настоящим Chrome.
//!   server: ServerHello (с echo session_id клиента!) + CCS +
//!     «зашифрованный» флайт EE/Certificate/CertificateVerify/Finished
//!     (4 записи application_data правдоподобных размеров) — как настоящий
//!     TLS 1.3-сервер.
//!   данные: записи [17 03 03 len u16 BE], len = payload + 16 (псевдо-тег
//!     GCM), максимум 16400 — в точности как AECD-записи Chrome.
//!   закрытие: close_notify — запись 0x17 len=18 [01 00][16 шума], перед FIN.
//!
//! БЫСТРО: одна операция writeAll на TLS-запись (заголовок+payload+тег
//! собираются в стейджинг-буфере); весь косметический шум — быстрый PRNG
//! (DefaultPrng, seed от CSPRNG при init), io.random — только для random/
//! session_id (по одному разу на соединение). Ноль аллокаций на кадр.
//!
//! ЧЕСТНАЯ ГРАНИЦА: это маскировка, а не TLS. Активный MITM, который
//! терминирует настоящий TLS, увидит подделку (наши ключи — шум, тег —
//! PRNG). От пассивного DPI (JA3/JA4, разбор записей, размеры) защищает.
//! Тайминг-анализ (Finished без RTT-паузы после ClientHello) не имитируем.
//! SNI выбирается случайно из списка невинных доменов; реальный обход
//! IP-whitelist — задача релея (docs/ROADMAP.md).
//!
//! СОВМЕСТИМОСТЬ: обрамление v2 несовместимо с кором, у которого faketls
//! первого поколения (записи без тега, урезанный ClientHello) — обе стороны
//! должны быть одного релиза (прецедент: sealed frames/epoch, PROTOCOL §19).
//!
//! Порядок байтов: заголовки записей — big-endian, как в настоящем TLS
//! (часть маскировки). Внутренние слои (obf, конверты) — LE, как весь проект.
const std = @import("std");
const interfaces = @import("../core/interfaces.zig");

pub const Error = interfaces.ConnError;

/// Роль: dialer = client (первым шлёт ClientHello), acceptor = server.
pub const Role = enum { client, server };

/// Тип записи TLS.
const rec_handshake: u8 = 0x16;
const rec_ccs: u8 = 0x14;
const rec_data: u8 = 0x17;

/// Максимум plaintext в одной записи TLS.
const record_max: usize = 16384;
/// Псевдо-тег AEAD: каждая запись данных на проводе длиннее payload на 16.
const fake_tag_len: usize = 16;
/// Максимум записи на проводе: 16384+16 = 0x4010, в точности как Chrome.
const wire_max: usize = record_max + fake_tag_len;
/// Минимум записи данных: 1 байт plaintext + тег.
const wire_min: usize = 1 + fake_tag_len;
/// Запись Finished: 36 байт «plaintext» + тег = 52 (как настоящий TLS 1.3).
const fin_wire_len: usize = 52;
/// Запись close_notify: alert 2 байта + тег = 18 (как настоящий).
const close_wire_len: usize = 18;
/// Зашифрованных записей в серверном флайте: EE, Cert, CV, Finished.
const srv_flight_data_records: usize = 4;

/// «Невинные» SNI: крупный CDN/хостинг, ничем не примечательны для Chrome.
const sni_list = [_][]const u8{
    "www.cloudflare.com",
    "ajax.googleapis.com",
    "cdn.jsdelivr.net",
    "fonts.gstatic.com",
    "www.microsoft.com",
    "download.windowsupdate.com",
    "www.google.com",
    "www.gstatic.com",
    "fonts.googleapis.com",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "www.youtube.com",
};

// ==== Шаблон ClientHello реального Chrome ====

/// Полная первая запись TLS реального Google Chrome 155.0.8059.40 (macOS
/// arm64, TCP, TLS 1.3, свежий профиль), захват 2026-10-06 из открытого
/// репозитория uTLS (testdata/chrome155_clienthello.hex) — независимый
/// дамп браузера, не синтетика. 1955 байт. Случайные поля (random,
/// session_id, GREASE-поинты, кейшеры, ECH-шум) заменяются на соединение.
const ch_template_hex = "160301079e0100079a030397ba84e6911f26dc308204a2e65a2264ea769abc71617e9832e8a05327e2c03f20130452c827a0b862598e1f621324a0887d19f386284186f43e136844ed39fbb200201a1a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000731fafa000000120000ca3400ba00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090ffe0d00da00000100014200200b81d7a0c9bb3d4482028d5f90d7ed4f702aa257f7621d379be6d154251e745b00b0573e4731d509ac8e562a21f30236277f71fef7f0bd518c2c9916022a74afcb7d4d6145d72ee33f2f3720f85df5d6840bf3ce4dde5bc3efdacda6d4116add75ced6fa8c993692791f9437400ea835ff5f57776025cc7ff2828a93fff832dc24a1e394cf503813d67c4f45b0580f68d16fcaf5d774ac28a4bedac83733318c7cca132bebd041bba4077e53f51a2e30018559b2ed802ecf7398d369ab3090b8c4eb257b197631fad183682d83c8b40f82be001b0003020002000a000c000a7a7a11ec001d00170018ff0100010000230000002b0007065a5a030403030010000e000c02683208687474702f312e31000b00020100003304ef04ed7a7a00010011ec04c049c251fae6095e3992e4517d82ba97a8c7a789c66f450b0d9c3579870445f17856d8e0c53dfb643fe54032044236154d1fd722e7f6c3bf3606e84a68775638e765a7fdb85672dc3768941eaf232a55b229fe58cb41e35683b0532ff873249acd08ac19f79091c1acb54c53459d9ca31ac998ca6a67f172a1ef9b839151797e78589ca4aee75056be454adb070f6622577abc664b353fbc2272bf4c8cea7724dad8bfa0617d21555e3d0b69de388505b01d00ec263334c535c99699b20d8cd741f48646aea8c519334623ab33ea990701d7c400e48415da30a468953d5bbdc684aa78f1aca5c591a1805b69a786257099f5a02a833339bb9794dccc40b9188dd189596039623d76534ac1481e695b38974c5738a8107a16f5d4c19cd51d52c70bde8566b8500c73bba0e55ba09e067c6d3c76ddb99ae7da0fb7950d344bc86b1ac36827ae483a0ded32be2f897f66b96100440f6e148be9c19a3c1c7504e01eef443d4a674043e41f4f3c70029801a756227e5c95041053138472b19a103d95807ec57c02316499e72362642fe0c418c2306cdfb44dee570bc2783596a1464d5a16e4d59cb1bcb967e4459ce0430787141b547abeda15c418acd2f095addac18866cd99b2c70b3087c1b070f95320853a33b3d4bf9edca3cdf2b4a96c74154b57aab782d3e97d1801b95c2b586b7a0ca38bafc4d987ee600585ac8c359bc9c89997ed1231d87b28c0e32f90e16778a29cc2d3c4dbea79db389df497cf2210bd4dd46d7d21a6b3b683eb040bfca87019ec921b3a3ae7f20eb90a95449b70c2740fe4ea2c16e1c01ba5367676b48f58a6d7d657a52c61737b1671214b1210252107b441cc5c968a998616a77047a3d7516f28ac92438287b6bb178024566ce4a1b6f11efe9abb73894605b313567c60693c13f156a6fb55304134007c69128249a381281099a50cd18b0873a1697045bc8224bec2f87e4b09002703766e87b2c8845f56a7b77385562f41644710a36f9388fb4ab1311482b61c056b171919b3ac3b8cbf38e1971686ceead326e4654ded168b8ed8064b3032f23a7793c51700b9ba0cfbbc39390f3c82256898bb1933c1fec6cae242772e7b4076a6cf0d996c7cb6960930bea5a384083a18c00883ced91206c6401fb45b75fb44d073726d5bcaeffabd077705816c7ec7b03b0468a1f7238c660ac5f34b86b12968338c2817f45197cb04c5db396c4a13dc6a104663b57f43bad5063591c63d9cac2a199885a048809246bbd20191f211080d7286c7b61525382dada5ab9c175913cc0c9a011c4217575d1756d1e4b6b1da94b8cc1321a269d0310eb0374fe4bb39e41673d7742f335191290aaf3ec846a0d209546a97707938b3a307fe191599b59b26e1cfc92b6c69818a8de06c6e6215ce20c1057a8f7ed6912a5a89d64447aaa5b3b5a27cd41b8715fb44a502697e3185ca005077a194cfd2ce4b44cc3d5c7538e60718e90247ac1912329bf8e7c7e03078601b93a11163d5b0c1b34b1358608dfc282ebc18bd20f5a35c610e59c09f200875f05c10de1c7f27dc050296a49d4a03469c365f16a9b9a6c5def522832718e8022440019ad0d662237bb3535b912fab358c9a89fc944c201afe4a3c4d65837b31e2eb034759da63d960226e2669b646b549d3161427956172e60d876d0353ab787ac5cad550790a65ef062efbbf97f65f1cf62d001d0020d6b7a093831d73daf8e2aa6d7106321215cce52e6d14c408a0dafe217a207654000d001a0018aaaa0904090509060403080404010503080505010806060100170000002d0002010100050005010000000000000014001200000f7777772e6578616d706c652e636f6d44cd00050003026832caca000100";
const ch_template_len = 1955;
const ch_template = blk: {
    @setEvalBranchQuota(200_000);
    var b: [ch_template_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, ch_template_hex) catch
        @compileError("шаблон ClientHello: битый hex");
    break :blk b;
};

/// Оффсет поля extensions_len в шаблоне (и в собранном ClientHello:
/// префикс до него байт-в-байт).
const ch_exts_len_off: usize = 112;
/// Начало списка расширений.
const ch_exts_off: usize = 114;

/// Чем заполнить расширение при сборке.
const ExtKind = enum {
    /// Копия из шаблона как есть.
    verbatim,
    /// + случайный GREASE-поинт в supported_groups.
    groups,
    /// + случайный GREASE-поинт в supported_versions.
    versions,
    /// + случайный GREASE-поинт в signature_algorithms.
    sig_algs,
    /// + GREASE-группа и случайные кейшеры X25519MLKEM768 (1216) и x25519 (32).
    key_share,
    /// Тело ECH-grease — случайный шум (длина из захвата).
    ech,
    /// server_name — собирается из списка доменов.
    sni,
};

const ExtDef = struct { off: u16, len: u16, kind: ExtKind };

/// Средние расширения (между первым и последним GREASE) в порядке захвата.
/// Порядок перемешивается на каждое соединение — как BoringSSL/Chrome
/// (GREASE-расширения остаются первым и последним).
const ch_exts = [17]ExtDef{
    .{ .off = 118, .len = 4, .kind = .verbatim }, // 0x0012 signed_certificate_timestamp
    .{ .off = 122, .len = 190, .kind = .verbatim }, // 0xca34 trust_anchors (28 ID)
    .{ .off = 312, .len = 222, .kind = .ech }, // 0xfe0d ECH grease
    .{ .off = 534, .len = 7, .kind = .verbatim }, // 0x001b compress_certificate
    .{ .off = 541, .len = 16, .kind = .groups }, // 0x000a supported_groups
    .{ .off = 557, .len = 5, .kind = .verbatim }, // 0xff01 renegotiation_info
    .{ .off = 562, .len = 4, .kind = .verbatim }, // 0x0023 session_ticket (пустой)
    .{ .off = 566, .len = 11, .kind = .versions }, // 0x002b supported_versions
    .{ .off = 577, .len = 18, .kind = .verbatim }, // 0x0010 ALPN h2,http/1.1
    .{ .off = 595, .len = 6, .kind = .verbatim }, // 0x000b EC point formats
    .{ .off = 601, .len = 1267, .kind = .key_share }, // 0x0033 key_share
    .{ .off = 1868, .len = 30, .kind = .sig_algs }, // 0x000d signature_algorithms
    .{ .off = 1898, .len = 4, .kind = .verbatim }, // 0x0017 extended_master_secret
    .{ .off = 1902, .len = 6, .kind = .verbatim }, // 0x002d psk_key_exchange_modes
    .{ .off = 1908, .len = 9, .kind = .verbatim }, // 0x0005 status_request
    .{ .off = 1917, .len = 24, .kind = .sni }, // 0x0000 server_name (динамический)
    .{ .off = 1941, .len = 9, .kind = .verbatim }, // 0x44cd ALPS
};

/// Буфер сборки клиентского флайта: CH (шаблон 1955 + запас на SNI) + CCS + Fin.
const ch_buf_len: usize = 2112;

/// Буфер сборки серверного флайта: SH(127)+CCS(6)+EE(61)+Cert(3605)+CV(269)+Fin(57).
const srv_flight_buf_len: usize = 4200;

/// Одно из 16 канонических GREASE-значений (0x0a0a..0xfafa), низкий ниббл 0x0a.
fn greaseValue(rng: std.Random) u8 {
    const i = rng.uintLessThan(u8, 16);
    return i * 16 + 0x0a;
}

/// Записать GREASE-поинт (два одинаковых байта) в dst.
fn grease(dst: *[2]u8, rng: std.Random) void {
    const g = greaseValue(rng);
    dst[0] = g;
    dst[1] = g;
}

/// Собрать клиентский флайт в buf (не меньше ch_buf_len): ClientHello +
/// CCS (compat-режим) + запись Finished (52). Побайтово направление
/// client→server совпадает с настоящим Chrome (тайминг Fin — см. доку
/// модуля). io — CSPRNG для random/session_id (по одному вызову на
/// соединение), rng — быстрый PRNG для GREASE/кейшеров/ECH/порядка.
fn buildClientHello(buf: []u8, io: std.Io, rng: std.Random, sni: []const u8) []const u8 {
    var n: usize = 0;
    // запись (legacy-версия 03 01) + заголовок рукопожатия; длины — в конце
    buf[0] = rec_handshake;
    buf[1] = 0x03;
    buf[2] = 0x01;
    buf[5] = 0x01; // client_hello
    n = 9;
    // legacy_version 03 03 + random 32
    buf[9] = 0x03;
    buf[10] = 0x03;
    n = 11;
    io.random(buf[11..43]);
    n = 43;
    // session_id: 32 случайных байта (compat-стиль Chrome)
    buf[43] = 32;
    io.random(buf[44..76]);
    n = 76;
    // шифры + компрессия — из шаблона, первый шифр становится GREASE
    @memcpy(buf[76..112], ch_template[76..112]);
    grease(buf[78..80], rng);
    n = ch_exts_len_off;
    n += 2; // extensions_len — патчим в конце
    // первое GREASE-расширение (пустое) — остаётся первым при перестановке
    {
        const g = greaseValue(rng);
        buf[n] = g;
        buf[n + 1] = g;
        buf[n + 2] = 0;
        buf[n + 3] = 0;
        n += 4;
    }
    // средние расширения в перемешанном порядке
    var order: [ch_exts.len]u8 = undefined;
    for (&order, 0..) |*o, i| o.* = @intCast(i);
    rng.shuffle(u8, &order);
    for (order) |idx| {
        const def = ch_exts[idx];
        switch (def.kind) {
            .verbatim => {
                @memcpy(buf[n..][0..def.len], ch_template[def.off..][0..def.len]);
                n += def.len;
            },
            .groups, .sig_algs => {
                @memcpy(buf[n..][0..def.len], ch_template[def.off..][0..def.len]);
                grease(buf[n + 6 ..][0..2], rng); // GREASE в начале списка
                n += def.len;
            },
            .versions => {
                @memcpy(buf[n..][0..def.len], ch_template[def.off..][0..def.len]);
                grease(buf[n + 5 ..][0..2], rng); // GREASE-версия после счётчика
                n += def.len;
            },
            .key_share => {
                // [shares_len][grease: grp 1B][11ec: 1216B][001d: 32B]
                @memcpy(buf[n..][0..def.len], ch_template[def.off..][0..def.len]);
                grease(buf[n + 6 ..][0..2], rng); // GREASE-группа
                rng.bytes(buf[n + 15 ..][0..1216]); // X25519MLKEM768
                rng.bytes(buf[n + 235 ..][0..32]); // x25519
                n += def.len;
            },
            .ech => {
                // тип+len из шаблона, тело — случайный шум (ECH-grease opaque)
                @memcpy(buf[n..][0..4], ch_template[def.off..][0..4]);
                rng.bytes(buf[n + 4 ..][0 .. def.len - 4]);
                n += def.len;
            },
            .sni => {
                // [0000][ext_len][list_len][00 host_name][name_len][name]
                const name_len: u16 = @intCast(sni.len);
                const body_len: u16 = 2 + 1 + 2 + name_len;
                buf[n] = 0x00;
                buf[n + 1] = 0x00;
                std.mem.writeInt(u16, buf[n + 2 ..][0..2], body_len, .big);
                std.mem.writeInt(u16, buf[n + 4 ..][0..2], 1 + 2 + name_len, .big);
                buf[n + 6] = 0x00;
                std.mem.writeInt(u16, buf[n + 7 ..][0..2], name_len, .big);
                @memcpy(buf[n + 9 ..][0..sni.len], sni);
                n += 9 + sni.len;
            },
        }
    }
    // последнее GREASE-расширение (1 байт 00) — остаётся последним
    {
        const g = greaseValue(rng);
        buf[n] = g;
        buf[n + 1] = g;
        buf[n + 2] = 0;
        buf[n + 3] = 1;
        buf[n + 4] = 0;
        n += 5;
    }
    // длины: extensions, handshake, запись
    std.mem.writeInt(u16, buf[ch_exts_len_off..][0..2], @intCast(n - ch_exts_off), .big);
    std.mem.writeInt(u24, buf[6..9], @intCast(n - 9), .big);
    std.mem.writeInt(u16, buf[3..5], @intCast(n - 5), .big);
    // ChangeCipherSpec (middlebox compat) — сразу после ClientHello
    buf[n] = rec_ccs;
    buf[n + 1] = 0x03;
    buf[n + 2] = 0x03;
    buf[n + 3] = 0x00;
    buf[n + 4] = 0x01;
    buf[n + 5] = 0x01;
    n += 6;
    // Finished: «зашифрованная» запись 52 (36 «plaintext» + тег), шум
    n = flightRecord(buf, n, fin_wire_len, rng);
    return buf[0..n];
}

/// Одна «зашифрованная» запись серверного флайта: [17 03 03 len][len шума].
fn flightRecord(buf: []u8, n: usize, len: u16, rng: std.Random) usize {
    buf[n] = rec_data;
    buf[n + 1] = 0x03;
    buf[n + 2] = 0x03;
    std.mem.writeInt(u16, buf[n + 3 ..][0..2], len, .big);
    rng.bytes(buf[n + 5 ..][0..len]);
    return n + 5 + len;
}

/// Собрать серверный флайт: ServerHello (echo session_id) + CCS +
/// 4 «зашифрованные» записи (EE, Certificate, CV, Finished) со случайным
/// содержимым правдоподобных размеров. sid == null — CH ещё не читали
/// (нет session_id для echo) — случайные байты.
fn buildServerFlight(buf: []u8, io: std.Io, rng: std.Random, sid: ?*const [32]u8) []const u8 {
    // ServerHello
    var n: usize = 0;
    buf[0] = rec_handshake;
    buf[1] = 0x03;
    buf[2] = 0x03;
    buf[5] = 0x02; // server_hello
    n = 9;
    buf[9] = 0x03;
    buf[10] = 0x03;
    n = 11;
    io.random(buf[11..43]); // random 32
    n = 43;
    buf[43] = 32; // session_id echo
    if (sid) |s| {
        @memcpy(buf[44..76], s);
    } else {
        io.random(buf[44..76]);
    }
    n = 76;
    buf[76] = 0x13; // TLS_AES_128_GCM_SHA256
    buf[77] = 0x01;
    buf[78] = 0x00; // компрессия null
    n = 79;
    n += 2; // extensions_len — патчим ниже
    // supported_versions: TLS 1.3
    buf[n] = 0x00;
    buf[n + 1] = 0x2b;
    buf[n + 2] = 0x00;
    buf[n + 3] = 0x02;
    buf[n + 4] = 0x03;
    buf[n + 5] = 0x04;
    n += 6;
    // key_share x25519: 32 случайных байта
    buf[n] = 0x00;
    buf[n + 1] = 0x33;
    std.mem.writeInt(u16, buf[n + 2 ..][0..2], 36, .big);
    buf[n + 4] = 0x00;
    buf[n + 5] = 0x1d;
    std.mem.writeInt(u16, buf[n + 6 ..][0..2], 32, .big);
    io.random(buf[n + 8 ..][0..32]);
    n += 40;
    std.mem.writeInt(u16, buf[79..81], @intCast(n - 81), .big);
    std.mem.writeInt(u24, buf[6..9], @intCast(n - 9), .big);
    std.mem.writeInt(u16, buf[3..5], @intCast(n - 5), .big);
    // ChangeCipherSpec (middlebox compat)
    buf[n] = rec_ccs;
    buf[n + 1] = 0x03;
    buf[n + 2] = 0x03;
    buf[n + 3] = 0x00;
    buf[n + 4] = 0x01;
    buf[n + 5] = 0x01;
    n += 6;
    // «зашифрованный» флайт: EncryptedExtensions, (Compressed)Certificate,
    // CertificateVerify, Finished — размеры как у настоящего сервера
    const ee_len = rng.intRangeAtMost(u16, 36, 56);
    const cert_len = rng.intRangeAtMost(u16, 1200, 3600);
    n = flightRecord(buf, n, ee_len, rng);
    n = flightRecord(buf, n, cert_len, rng);
    n = flightRecord(buf, n, 264, rng); // CertificateVerify (ecdsa/r ~264)
    n = flightRecord(buf, n, fin_wire_len, rng); // Finished: 36+16
    return buf[0..n];
}

/// Длина записи из 5-байтового заголовка (u16 BE).
fn wireLen(hdr: [5]u8) usize {
    return (@as(usize, hdr[3]) << 8) | hdr[4];
}

/// Обёртка Conn: TLS-подобный поток. Первый write отправляет fake-рукопожатие
/// (client: CH+CCS+Finished; server: SH+CCS+флайт), первый read поглощает
/// рукопожатие пира. Далее — записи application_data с псевдо-тегом AECD.
pub const FakeTlsConn = struct {
    inner: interfaces.Conn,
    alloc: std.mem.Allocator,
    io: std.Io,
    role: Role,
    /// Быстрый PRNG косметического шума (теги/GREASE/флайт/порядок). НЕ
    /// криптографический и не должен им быть: полезная нагрузка выше по
    /// стеку уже шифруется AEAD-сессией, шум нужен только для правдоподобия
    /// проводного вида. Seed — CSPRNG при init.
    prng: std.Random.DefaultPrng,
    hello_sent: bool = false,
    hello_read: bool = false,
    /// session_id пира (роль server): echo в ServerHello. Пишется rx-стороной
    /// при skipPeerHello, читается tx-стороной при первом write; в проде
    /// первый write всегда позже первого read (m1 -> m2), гонки нет.
    peer_sid: [32]u8 = undefined,
    peer_sid_valid: bool = false,
    /// Одна аллокация на соединение: [rbuf][wbuf].
    mem: []u8,
    /// Буфер тела текущей записи (чтение), включая псевдо-тег.
    rbuf: []u8,
    rlen: usize = 0,
    rpos: usize = 0,
    /// Стейджинг записи: [hdr 5][payload <= 16384][tag 16] -> один writeAll.
    wbuf: []u8,

    const rbuf_len = wire_max;
    const wbuf_len = 5 + record_max + fake_tag_len;

    const vtable = interfaces.Conn.VTable{
        .readAll = readAllImpl,
        .writeAll = writeAllImpl,
        .close = closeImpl,
    };

    /// Аллокация: rbuf+wbuf одним куском. error.Closed — память.
    pub fn init(alloc: std.mem.Allocator, io: std.Io, inner: interfaces.Conn, role: Role) Error!FakeTlsConn {
        const mem = alloc.alloc(u8, rbuf_len + wbuf_len) catch return error.Closed;
        var seed: [8]u8 = undefined;
        io.random(&seed);
        return .{
            .inner = inner,
            .alloc = alloc,
            .io = io,
            .role = role,
            .prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed, .little)),
            .mem = mem,
            .rbuf = mem[0..rbuf_len],
            .wbuf = mem[rbuf_len..],
        };
    }

    pub fn deinit(self: *FakeTlsConn) void {
        self.alloc.free(self.mem);
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

    fn readHdr(self: *FakeTlsConn, hdr: *[5]u8) Error!void {
        try self.innerRead(hdr);
    }

    /// Прочитать тело записи в rbuf (len <= wire_max).
    fn readBody(self: *FakeTlsConn, len: usize) Error!void {
        try self.innerRead(self.rbuf[0..len]);
    }

    /// Прочитать и проверить CCS (compat-режим: ровно 1 байт 01).
    fn expectCcs(self: *FakeTlsConn) Error!void {
        var hdr: [5]u8 = undefined;
        try self.readHdr(&hdr);
        if (hdr[0] != rec_ccs or hdr[1] != 0x03 or hdr[2] != 0x03 or wireLen(hdr) != 1)
            return error.Tampered;
        try self.readBody(1);
        if (self.rbuf[0] != 0x01) return error.Tampered;
    }

    /// Пропустить рукопожатие пира.
    /// server: ClientHello (вытащить session_id) + CCS + Finished(52).
    /// client: ServerHello + CCS + 4 «зашифрованные» записи флайта.
    fn skipPeerHello(self: *FakeTlsConn) Error!void {
        var hdr: [5]u8 = undefined;
        switch (self.role) {
            .server => {
                try self.readHdr(&hdr);
                if (hdr[0] != rec_handshake or hdr[1] != 0x03) return error.Tampered;
                const ch_len = wireLen(hdr);
                if (ch_len < 76 or ch_len > wire_max) return error.Tampered;
                try self.readBody(ch_len);
                const b = self.rbuf[0..ch_len];
                // [hs_type 01][len 3][03 03][random 32][sid_len][sid 32]
                if (b[0] != 0x01 or b[38] != 32) return error.Tampered;
                self.peer_sid = b[39..71].*;
                self.peer_sid_valid = true;
                try self.expectCcs();
                // клиентский Finished: одна запись 0x17 длиной 52
                try self.readHdr(&hdr);
                if (hdr[0] != rec_data or wireLen(hdr) != fin_wire_len) return error.Tampered;
                try self.readBody(fin_wire_len);
            },
            .client => {
                try self.readHdr(&hdr);
                if (hdr[0] != rec_handshake or hdr[1] != 0x03 or hdr[2] != 0x03)
                    return error.Tampered;
                const sh_len = wireLen(hdr);
                if (sh_len < 40 or sh_len > wire_max) return error.Tampered;
                try self.readBody(sh_len);
                if (self.rbuf[0] != 0x02) return error.Tampered; // server_hello
                try self.expectCcs();
                var i: usize = 0;
                while (i < srv_flight_data_records) : (i += 1) {
                    try self.readHdr(&hdr);
                    if (hdr[0] != rec_data) return error.Tampered;
                    const len = wireLen(hdr);
                    if (len == 0 or len > wire_max) return error.Tampered;
                    if (i == srv_flight_data_records - 1 and len != fin_wire_len)
                        return error.Tampered;
                    try self.readBody(len);
                }
            },
        }
        self.hello_read = true;
    }

    /// Читает ровно dest.len байт потока (тела записей 0x17 без тега).
    fn readAllImpl(ptr: *anyopaque, dest: []u8) Error!void {
        const self: *FakeTlsConn = @ptrCast(@alignCast(ptr));
        if (!self.hello_read) try self.skipPeerHello();
        var off: usize = 0;
        while (off < dest.len) {
            if (self.rpos >= self.rlen) {
                // следующая запись: [17 03 03 len u16 BE][тело len][тег 16]
                var hdr: [5]u8 = undefined;
                try self.readHdr(&hdr);
                if (hdr[0] != rec_data or hdr[1] != 0x03 or hdr[2] != 0x03)
                    return error.Tampered;
                const len = wireLen(hdr);
                if (len < wire_min or len > wire_max) return error.Tampered;
                try self.readBody(len);
                // close_notify пира: [01 00] + тег -> чистый EOF-семантика.
                // Пара [01 00] зарезервирована: прикладные writeAll не пишут
                // 2-байтовый payload [01 00] (m1-заголовок — [40 00],
                // минимальный obf-кадр — 128 байт).
                if (len == close_wire_len and self.rbuf[0] == 0x01 and self.rbuf[1] == 0x00)
                    return error.Closed;
                self.rlen = len - fake_tag_len;
                self.rpos = 0;
            }
            const avail = self.rlen - self.rpos;
            const n = @min(dest.len - off, avail);
            @memcpy(dest[off..][0..n], self.rbuf[self.rpos..][0..n]);
            self.rpos += n;
            off += n;
        }
    }

    /// Пишет буфер записями application_data (payload + псевдо-тег AECD),
    /// каждую — ОДНОЙ операцией writeAll (стейджинг в wbuf).
    fn writeAllImpl(ptr: *anyopaque, buf: []const u8) Error!void {
        const self: *FakeTlsConn = @ptrCast(@alignCast(ptr));
        if (!self.hello_sent) {
            switch (self.role) {
                .client => {
                    var hb: [ch_buf_len]u8 = undefined;
                    const sni = sni_list[self.prng.random().uintLessThan(usize, sni_list.len)];
                    const hello = buildClientHello(&hb, self.io, self.prng.random(), sni);
                    try self.innerWrite(hello);
                },
                .server => {
                    var fb: [srv_flight_buf_len]u8 = undefined;
                    const sid: ?*const [32]u8 = if (self.peer_sid_valid) &self.peer_sid else null;
                    const hello = buildServerFlight(&fb, self.io, self.prng.random(), sid);
                    try self.innerWrite(hello);
                },
            }
            self.hello_sent = true;
        }
        var rest = buf;
        while (rest.len > 0) {
            const n = @min(rest.len, record_max);
            self.wbuf[0] = rec_data;
            self.wbuf[1] = 0x03;
            self.wbuf[2] = 0x03;
            std.mem.writeInt(u16, self.wbuf[3..5], @intCast(n + fake_tag_len), .big);
            @memcpy(self.wbuf[5..][0..n], rest[0..n]);
            self.prng.random().bytes(self.wbuf[5 + n ..][0..fake_tag_len]);
            try self.innerWrite(self.wbuf[0 .. 5 + n + fake_tag_len]);
            rest = rest[n..];
        }
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *FakeTlsConn = @ptrCast(@alignCast(ptr));
        // close_notify: запись [17 03 03 00 12][01 00][16 шума] — как alert
        // warning/close_notify настоящего TLS. Хвост — CSPRNG (prng может
        // в этот момент использоваться конкурентным writeAll). Ошибки
        // записи игнорируем: сокет и так закрываем.
        var cn: [5 + close_wire_len]u8 = undefined;
        cn[0] = rec_data;
        cn[1] = 0x03;
        cn[2] = 0x03;
        cn[3] = 0;
        cn[4] = close_wire_len;
        cn[5] = 0x01;
        cn[6] = 0x00;
        self.io.random(cn[7..]);
        self.innerWrite(&cn) catch {};
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

/// Счётчик операций writeAll внутреннего Conn (проверка «1 syscall на запись»).
const Counting = struct {
    inner: interfaces.Conn,
    writes: usize = 0,

    const vtable = interfaces.Conn.VTable{
        .readAll = readImpl,
        .writeAll = writeImpl,
        .close = closeImpl,
    };
    fn readImpl(ptr: *anyopaque, buf: []u8) Error!void {
        const self: *Counting = @ptrCast(@alignCast(ptr));
        return self.inner.readAll(buf);
    }
    fn writeImpl(ptr: *anyopaque, buf: []const u8) Error!void {
        const self: *Counting = @ptrCast(@alignCast(ptr));
        self.writes += 1;
        return self.inner.writeAll(buf);
    }
    fn closeImpl(ptr: *anyopaque) void {
        const self: *Counting = @ptrCast(@alignCast(ptr));
        self.inner.close();
    }
    fn conn(self: *Counting) interfaces.Conn {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

/// Пройти рукопожатие и обменяться сообщениями. Порядок — как в проде:
/// клиент пишет первым, сервер сначала читает (его флайт эхает session_id),
/// потом отвечает, клиент читает ответ.
fn handshakeEcho(wa: interfaces.Conn, wb: interfaces.Conn, msg_a: []const u8, msg_b: []const u8, ra: []u8, rb: []u8) !void {
    try wa.writeAll(msg_a);
    try wb.readAll(rb);
    try wb.writeAll(msg_b);
    try wa.readAll(ra);
    try testing.expectEqualStrings(msg_a, rb);
    try testing.expectEqualStrings(msg_b, ra);
}

/// Разобрать расширения ClientHello/ServerHello: возвращает количество и
/// заполняет types (в порядке на проводе).
fn parseExts(data: []const u8, types: []u16) !usize {
    const exts_len = std.mem.readInt(u16, data[ch_exts_len_off..][0..2], .big);
    var o: usize = ch_exts_off;
    const end = o + exts_len;
    var count: usize = 0;
    while (o + 4 <= end) {
        const t = std.mem.readInt(u16, data[o..][0..2], .big);
        const l = std.mem.readInt(u16, data[o + 2 ..][0..2], .big);
        if (o + 4 + l > end) return error.Tampered;
        types[count] = t;
        count += 1;
        o += 4 + l;
    }
    if (o != end) return error.Tampered;
    return count;
}

/// Проверить, что u16 — каноническое GREASE-значение (0x0a0a..0xfafa).
fn isGrease(t: u16) bool {
    return (t >> 8) == (t & 0xff) and (t & 0x0f) == 0x0a and (t >> 8) >= 0x0a;
}

test "faketls: эхо клиент<->сервер, провод как настоящий TLS 1.3" {
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
    var rbuf_a: [msg_b.len]u8 = undefined;
    var rbuf_b: [msg_a.len]u8 = undefined;
    try handshakeEcho(wa.conn, wb.conn, msg_a, msg_b, &rbuf_a, &rbuf_b);
    // большой буфер через несколько записей
    var big: [40000]u8 = undefined;
    testing.io.random(&big);
    try wa.conn.writeAll(&big);
    var big2: [40000]u8 = undefined;
    try wb.conn.readAll(&big2);
    try testing.expectEqualSlices(u8, &big, &big2);

    // === провод A->B (client): CH, CCS, Finished(52), данные (+16) ===
    const a2b = pipe.a2b.items;
    try testing.expect(a2b[0] == rec_handshake);
    try testing.expect(a2b[1] == 0x03 and a2b[2] == 0x01);
    const ch_len = wireLen(a2b[0..5].*);
    try testing.expect(ch_len >= 1900 and ch_len <= ch_buf_len);
    try testing.expect(a2b[5] == 0x01);
    try testing.expect(a2b[43] == 32); // session_id len
    // запись 2: CCS; запись 3: Finished 52; далее данные
    var o: usize = 5 + ch_len;
    try testing.expect(a2b[o] == rec_ccs and wireLen(a2b[o..][0..5].*) == 1);
    o += 6;
    try testing.expect(a2b[o] == rec_data and wireLen(a2b[o..][0..5].*) == fin_wire_len);
    o += 5 + fin_wire_len;
    // записи данных: len = payload + 16 (AECD-правдоподобие)
    var saw_data = false;
    while (o + 5 <= a2b.len) {
        const t = a2b[o];
        const l = wireLen(a2b[o..][0..5].*);
        try testing.expect(t == rec_data);
        try testing.expect(l >= wire_min and l <= wire_max);
        if (l == msg_a.len + fake_tag_len) saw_data = true; // msg_a + тег
        o += 5 + l;
    }
    try testing.expect(o == a2b.len);
    try testing.expect(saw_data);

    // === провод B->A (server): SH с echo sid, CCS, 4 записи флайта ===
    const b2a = pipe.b2a.items;
    try testing.expect(b2a[0] == rec_handshake);
    try testing.expect(b2a[1] == 0x03 and b2a[2] == 0x03);
    try testing.expect(b2a[5] == 0x02);
    const sh_len = wireLen(b2a[0..5].*);
    try testing.expect(sh_len == 122); // 5+4+2+32+1+32+2+1+2+6+40
    // session_id echo: байты 44..76 равны sid клиента из CH
    try testing.expectEqualSlices(u8, a2b[44..76], b2a[44..76]);
    var p: usize = 5 + sh_len;
    try testing.expect(b2a[p] == rec_ccs);
    p += 6;
    var i: usize = 0;
    while (i < srv_flight_data_records) : (i += 1) {
        const l = wireLen(b2a[p..][0..5].*);
        try testing.expect(b2a[p] == rec_data);
        if (i == srv_flight_data_records - 1) {
            try testing.expect(l == fin_wire_len);
        } else {
            try testing.expect(l > 0 and l <= wire_max);
        }
        p += 5 + l;
    }
    // после флайта — данные сервера
    try testing.expect(b2a[p] == rec_data and wireLen(b2a[p..][0..5].*) == msg_b.len + fake_tag_len);
}

test "faketls: ClientHello — байтовая структура Chrome" {
    var prng = std.Random.DefaultPrng.init(7);
    var buf: [ch_buf_len]u8 = undefined;
    const sni = "www.cloudflare.com";
    const hello = buildClientHello(&buf, testing.io, prng.random(), sni);
    try testing.expect(hello.len >= 1900);
    try testing.expect(hello[9] == 0x03 and hello[10] == 0x03); // legacy_version
    try testing.expect(hello[43] == 32); // session_id 32 байта
    // GREASE-шифр первый в списке
    try testing.expect(isGrease(std.mem.readInt(u16, hello[78..][0..2], .big)));
    // 19 расширений: GREASE, 17 средних, GREASE
    var types: [24]u16 = undefined;
    const count = try parseExts(hello, &types);
    try testing.expectEqual(@as(usize, 19), count);
    try testing.expect(isGrease(types[0]));
    try testing.expect(isGrease(types[18]));
    // ожидаемый набор средних расширений (захват Chrome 155)
    var sorted_types: [17]u16 = undefined;
    @memcpy(&sorted_types, types[1..18]);
    std.mem.sort(u16, &sorted_types, {}, std.sort.asc(u16));
    const expected = [_]u16{ 0x0000, 0x0005, 0x000a, 0x000b, 0x0010, 0x0012, 0x001b, 0x0017, 0x0023, 0x002b, 0x002d, 0x0033, 0x000d, 0x44cd, 0xca34, 0xfe0d, 0xff01 };
    var sorted_expected = expected;
    std.mem.sort(u16, &sorted_expected, {}, std.sort.asc(u16));
    try testing.expectEqualSlices(u16, &sorted_expected, &sorted_types);
    // key_share: 1263 байта тела (кейшеры MLKEM768 1216 + x25519 32 + служебные)
    for (types[1..18]) |t| {
        if (t == 0x0033) {
            const o = findExt(hello, 0x0033) orelse return error.TestUnexpectedResult;
            try testing.expectEqual(@as(u16, 1263), std.mem.readInt(u16, hello[o + 2 ..][0..2], .big));
        }
        if (t == 0x0000) {
            const o = findExt(hello, 0x0000) orelse return error.TestUnexpectedResult;
            // [ext_len][list_len][00][name_len][name]
            const name_len = std.mem.readInt(u16, hello[o + 7 ..][0..2], .big);
            try testing.expectEqual(@as(u16, sni.len), name_len);
            try testing.expectEqualSlices(u8, sni, hello[o + 9 ..][0..sni.len]);
        }
    }
}

/// Найти смещение расширения по типу (в собранном ClientHello).
fn findExt(data: []const u8, want: u16) ?usize {
    const exts_len = std.mem.readInt(u16, data[ch_exts_len_off..][0..2], .big);
    var o: usize = ch_exts_off;
    const end = o + exts_len;
    while (o + 4 <= end) {
        const t = std.mem.readInt(u16, data[o..][0..2], .big);
        if (t == want) return o;
        const l = std.mem.readInt(u16, data[o + 2 ..][0..2], .big);
        o += 4 + l;
    }
    return null;
}

test "faketls: порядок расширений рандомизирован, набор стабилен" {
    var orders: [8][19]u16 = undefined;
    for (0..8) |i| {
        var prng = std.Random.DefaultPrng.init(100 + i * 37);
        var buf: [ch_buf_len]u8 = undefined;
        const hello = buildClientHello(&buf, testing.io, prng.random(), "www.google.com");
        try testing.expectEqual(@as(usize, 19), try parseExts(hello, &orders[i]));
    }
    // не все порядки совпадают (перестановка Chrome)
    var differs = false;
    outer: for (1..8) |i| {
        for (0..19) |j| {
            if (orders[i][j] != orders[0][j]) {
                differs = true;
                break :outer;
            }
        }
    }
    try testing.expect(differs);
    // набор и границы (GREASE первым/последним) — одинаковы
    for (&orders) |*o| {
        try testing.expect(isGrease(o[0]));
        try testing.expect(isGrease(o[18]));
    }
}

test "faketls: ClientHello уникален на соединение (random/sid/кейшеры)" {
    var b1: [ch_buf_len]u8 = undefined;
    var b2: [ch_buf_len]u8 = undefined;
    var prng1 = std.Random.DefaultPrng.init(1);
    var prng2 = std.Random.DefaultPrng.init(2);
    const h1 = buildClientHello(&b1, testing.io, prng1.random(), "www.google.com");
    const h2 = buildClientHello(&b2, testing.io, prng2.random(), "www.google.com");
    try testing.expect(!std.mem.eql(u8, h1[11..43], h2[11..43])); // random
    try testing.expect(!std.mem.eql(u8, h1[44..76], h2[44..76])); // session_id
    const ks1 = findExt(h1, 0x0033) orelse return error.TestUnexpectedResult;
    const ks2 = findExt(h2, 0x0033) orelse return error.TestUnexpectedResult;
    // кейшеры (смещения внутри расширения) различаются
    try testing.expect(!std.mem.eql(u8, h1[ks1 + 19 ..][0..64], h2[ks2 + 19 ..][0..64]));
}

test "faketls: серверный флайт — SH с echo, CCS, 4 записи (Fin=52)" {
    var prng = std.Random.DefaultPrng.init(9);
    var buf: [srv_flight_buf_len]u8 = undefined;
    const sid: [32]u8 = @splat(0xAB);
    const fl = buildServerFlight(&buf, testing.io, prng.random(), &sid);
    try testing.expect(fl[0] == rec_handshake and fl[5] == 0x02);
    try testing.expect(fl[76] == 0x13 and fl[77] == 0x01); // AES-128-GCM
    try testing.expectEqualSlices(u8, &sid, fl[44..76]);
    const sh_len = wireLen(fl[0..5].*);
    try testing.expect(sh_len == 122);
    var o: usize = 5 + sh_len;
    try testing.expect(fl[o] == rec_ccs);
    o += 6;
    var lens: [srv_flight_data_records]usize = undefined;
    for (0..srv_flight_data_records) |i| {
        try testing.expect(fl[o] == rec_data);
        lens[i] = wireLen(fl[o..][0..5].*);
        o += 5 + lens[i];
    }
    try testing.expect(o == fl.len);
    try testing.expect(lens[0] >= 36 and lens[0] <= 56); // EE
    try testing.expect(lens[1] >= 1200 and lens[1] <= 3600); // Certificate
    try testing.expect(lens[2] == 264); // CertificateVerify
    try testing.expect(lens[3] == fin_wire_len); // Finished
}

test "faketls: close_notify — запись 18 байт, пир получает Closed" {
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
    const ca = "close-notify-test-A";
    const cb = "close-notify-test-B";
    var ra: [cb.len]u8 = undefined;
    var rb: [ca.len]u8 = undefined;
    try handshakeEcho(wa.conn, wb.conn, ca, cb, &ra, &rb);
    const before = pipe.a2b.items.len;
    wa.conn.close();
    const t = pipe.a2b.items;
    try testing.expectEqual(@as(usize, 23), t.len - before);
    const tail = t[t.len - 23 ..];
    try testing.expect(tail[0] == rec_data and tail[1] == 0x03 and tail[2] == 0x03);
    try testing.expect(tail[3] == 0 and tail[4] == close_wire_len);
    try testing.expect(tail[5] == 0x01 and tail[6] == 0x00);
    // пир: следующее чтение — close_notify -> Closed (EOF-семантика)
    var one: [1]u8 = undefined;
    try testing.expectError(error.Closed, wb.conn.readAll(&one));
}

test "faketls: битые записи — Tampered" {
    const cases = [_][5]u8{
        .{ 0x16, 0x03, 0x03, 0, 4 }, // тип не application_data
        .{ 0x17, 0x02, 0x03, 0, 20 }, // версия не 03 03
        .{ 0x17, 0x03, 0x03, 0, 5 }, // len < 17 (меньше тега)
        .{ 0x17, 0x03, 0x03, 0x40, 0x31 }, // len 16401 > максимума
    };
    for (cases) |bad| {
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
        const pa = "ping!!";
        const pb = "pong!!";
        var ra: [pb.len]u8 = undefined;
        var rb: [pa.len]u8 = undefined;
        try handshakeEcho(wa.conn, wb.conn, pa, pb, &ra, &rb);
        try pipe.b2a.appendSlice(testing.allocator, &bad);
        var one: [1]u8 = undefined;
        try testing.expectError(error.Tampered, wa.conn.readAll(&one));
    }
}

test "faketls: один writeAll внутреннего Conn на TLS-запись" {
    var pipe = Pipe{ .alloc = testing.allocator };
    defer {
        pipe.a2b.deinit(testing.allocator);
        pipe.b2a.deinit(testing.allocator);
    }
    var cnt = Counting{ .inner = pipe.sideA() };
    const wa = try wrap(testing.allocator, testing.io, cnt.conn(), .client);
    defer {
        wa.ftls.deinit();
        testing.allocator.destroy(wa.ftls);
    }
    // рукопожатие (CH+CCS+Fin) — один writeAll; каждая запись данных — один
    var hundred: [100]u8 = @splat('x');
    try wa.conn.writeAll(&hundred);
    try testing.expectEqual(@as(usize, 2), cnt.writes);
    // 40000 байт -> 3 записи (16384+16384+7232) -> +3 writeAll
    var big: [40000]u8 = undefined;
    try wa.conn.writeAll(&big);
    try testing.expectEqual(@as(usize, 5), cnt.writes);
}

test "faketls: e2e через настоящий TCP — rx-поток + tx, эхо 64 КБ" {
    const tcp = @import("tcp.zig");
    const alloc = testing.allocator;
    const ports = [_]u16{ 39611, 39623, 39637, 39641 };

    // слушатель на свободном порту
    var listener: ?tcp.Listener = null;
    var lport: u16 = 0;
    for (ports) |port| {
        var ab: [24]u8 = undefined;
        const a = std.fmt.bufPrint(&ab, "127.0.0.1:{d}", .{port}) catch unreachable;
        listener = tcp.listen(a) catch null;
        if (listener != null) {
            lport = port;
            break;
        }
    }
    var srv = listener orelse return error.Network;
    defer srv.deinit();

    // сервер: accept -> fake-TLS(.server) -> читает 64 КБ -> эхом назад
    // (как прод: сначала readAll m1, потом writeAll m2)
    var payload: [65536]u8 = undefined;
    testing.io.random(&payload);
    const th = try std.Thread.spawn(.{}, struct {
        fn run(l: *tcp.Listener, data: []const u8) void {
            const tc = l.accept(std.testing.allocator) catch return;
            defer {
                tc.deinit();
                std.testing.allocator.destroy(tc);
            }
            const w = wrap(std.testing.allocator, std.testing.io, tc.conn(), .server) catch return;
            defer {
                w.ftls.deinit();
                std.testing.allocator.destroy(w.ftls);
            }
            var got: [65536]u8 = undefined;
            w.conn.readAll(&got) catch return;
            w.conn.writeAll(data[0..got.len]) catch return;
        }
    }.run, .{ &srv, &payload });
    defer th.join();

    // клиент: dial (порт слушателя)
    var ab2: [24]u8 = undefined;
    const dial_addr = std.fmt.bufPrint(&ab2, "127.0.0.1:{d}", .{lport}) catch unreachable;
    const tc = try tcp.dial(alloc, dial_addr);
    const wa = try wrap(alloc, testing.io, tc.conn(), .client);
    defer {
        wa.ftls.deinit();
        alloc.destroy(wa.ftls);
        alloc.destroy(tc);
    }

    // rx-поток стартует ДО tx и блокируется в skipPeerHello, пока tx шлёт
    // данные — ровно как сессия (rx ждёт m2, tx пишет кадры)
    const Rx = struct {
        conn: interfaces.Conn,
        buf: *[65536]u8,
        ok: bool = false,
        fn run(self: *@This()) void {
            self.conn.readAll(self.buf) catch return;
            self.ok = true;
        }
    };
    var client_rx_buf: [65536]u8 = undefined;
    var rx = Rx{ .conn = wa.conn, .buf = &client_rx_buf };
    const rth = try std.Thread.spawn(.{}, Rx.run, .{&rx});
    try wa.conn.writeAll(&payload);
    rth.join();
    try testing.expect(rx.ok);
    try testing.expectEqualSlices(u8, &payload, rx.buf);

    // close_notify уходит на провод до FIN (сокет уже закрыт сервером —
    // запись может не дойти, ошибки не критичны)
    wa.conn.close();
}
