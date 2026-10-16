//! search — движок методов SEARCH_MESSAGE (23) и GLOBAL_SEARCH_MESSAGE
//! (24), api 2.1.0 (полный контракт — docs/CORE-API.md §4.3).
//!
//! Работает с уже разобранными записями лога (Rec: main.zig парсит
//! записи kind msg и валидирует хвост entities своим recEntityTail —
//! раскладка лога живёт в main.zig, здесь только семантика поиска).
//! Матчинг двухуровневый:
//! 1) точный — регистронезависимая подстрока (свёртка ASCII + кириллица);
//! 2) нечёткий — слово-уровневый Левенштейн по codepoint'ам с порогом
//!    max(1, query_codepoints/3), для однословного query.
//! Файл std-only (импорт api.zig относительный, как у invite.zig):
//! включён и в exe (main.zig), и в юнит-тест-корень (shopot_tests.zig).
//! Аллокаций на матчинг нет — только на индексы окна.
const std = @import("std");
const api = @import("api.zig");

/// Бит2 flags записи ответа: совпадение нечёткое (слово-Левенштейн),
/// а не точная подстрока. Биты 0/1 — mine/delivered, как в GET_HISTORY.
pub const flag_fuzzy: u8 = 0b100;

/// Заглушка хвоста entities «форматирования нет».
const zero_tail = [_]u8{0};

/// Разобранная запись лога kind msg (срезы указывают в исходный буфер
/// записи; хвост entities уже валидирован вызывающим).
pub const Rec = struct {
    cid: u32,
    /// Бит0 mine, бит1 delivered (передаётся в ответ как есть).
    flags: u8,
    msg_id: [16]u8,
    ts_ms: u64,
    body: []const u8,
    /// Хвост entities канонического формата (может быть пустым срезом).
    tail: []const u8,
    /// Размер записи на проводе ответа: flags+msg_id+ts+len+body+tail
    /// (без [cid u32] глобального режима — его добавляет writeResponse).
    size: usize,
};

/// Разобранные аргументы SEARCH_MESSAGE / GLOBAL_SEARCH_MESSAGE.
pub const Args = struct {
    /// null — глобальный поиск по всем чатам; иначе cid контакта.
    cid: ?u32,
    /// Подстрока поиска (сырые байты, обычно UTF-8).
    query: []const u8,
    /// 0 → 50 (подменяется в validate).
    limit: u32,
    /// Пропуск offset самых новых совпадений объединённого списка.
    offset: u32,
};

/// Разбор payload запроса. global=true — формат GLOBAL_SEARCH_MESSAGE
/// `[query str16][limit u32][offset u32]`; иначе SEARCH_MESSAGE
/// `[cid u32][query str16][limit u32][offset u32]`.
/// null → BAD_FRAME (обрезано/лишние байты).
pub fn parseArgs(payload: []const u8, global: bool) ?Args {
    var r = api.Reader.init(payload);
    var cid: ?u32 = null;
    if (!global) cid = r.readU32() catch return null;
    const query = r.readStr16() catch return null;
    const limit = r.readU32() catch return null;
    const offset = r.readU32() catch return null;
    if (r.hasMore()) return null;
    return .{ .cid = cid, .query = query, .limit = limit, .offset = offset };
}

/// Нормализация и проверка аргументов: limit 0 → 50, > 200 → TOO_BIG;
/// query пустой → BAD_ARGS, длиннее тела (4096) → TOO_BIG — совпасть
/// не может. OK → null, args.limit подменён.
pub fn validate(args: *Args) ?api.Status {
    if (args.limit == 0) args.limit = 50;
    if (args.limit > 200) return .TOO_BIG;
    if (args.query.len == 0) return .BAD_ARGS;
    if (args.query.len > 4096) return .TOO_BIG;
    return null;
}

// ------------------------------------------------------ регистронезависимость

/// Простое свёртывание регистра одного codepoint: ASCII A..Z,
/// кириллица А..Я (U+0410..U+042F) и Ё (U+0401) → нижний регистр.
/// Прочие скрипты — как есть (ограничение v1, см. CORE-API.md).
fn foldCp(cp: u21) u21 {
    if (cp >= 'A' and cp <= 'Z') return cp + 0x20;
    if (cp >= 0x0410 and cp <= 0x042F) return cp + 0x20;
    if (cp == 0x0401) return 0x0451;
    return cp;
}

/// Один шаг ленивого UTF-8-декодирования: codepoint + длина в байтах.
/// Некорректная последовательность — один сырой байт как codepoint
/// (ядро не валидирует UTF-8 тел по контракту entities).
const Cp = struct { cp: u21, len: usize };

fn nextCp(buf: []const u8, i: usize) Cp {
    const b = buf[i];
    const n = std.unicode.utf8ByteSequenceLength(b) catch
        return .{ .cp = b, .len = 1 };
    if (i + n > buf.len) return .{ .cp = b, .len = 1 };
    const cp = std.unicode.utf8Decode(buf[i .. i + n]) catch
        return .{ .cp = b, .len = 1 };
    return .{ .cp = cp, .len = n };
}

/// Число codepoint'ов в буфере (для порога Левенштейна).
fn cpLen(buf: []const u8) usize {
    var i: usize = 0;
    var n: usize = 0;
    while (i < buf.len) {
        i += nextCp(buf, i).len;
        n += 1;
    }
    return n;
}

/// Регистронезависимая подстрока: свёрнутые codepoint'ы needle идут
/// подряд среди свёрнутых codepoint'ов haystack (фразы с пробелами
/// работают). Классический вложенный скан, тела ≤ 4096 байт.
fn containsFold(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    var start: usize = 0;
    while (start < hay.len) {
        // стартовая позиция сдвигается на один codepoint haystack
        const step = nextCp(hay, start).len;
        var h = start;
        var j: usize = 0;
        var ok = true;
        while (j < needle.len) {
            if (h >= hay.len) {
                ok = false;
                break;
            }
            const hc = nextCp(hay, h);
            const nc = nextCp(needle, j);
            if (foldCp(hc.cp) != foldCp(nc.cp)) {
                ok = false;
                break;
            }
            h += hc.len;
            j += nc.len;
        }
        if (ok) return true;
        start += step;
    }
    return false;
}

// ------------------------------------------------------------- нечёткий матч

/// Разделители слов: пробельные и ASCII-пунктуация.
fn isSep(b: u8) bool {
    return switch (b) {
        ' ', '\t', '\n', '\r', 0x0B, 0x0C => true,
        '.', ',', '!', '?', ':', ';', '(', ')', '"', '\'', '-', '_', '/' => true,
        else => false,
    };
}

/// Итератор слов тела (срезы в buf, аллокаций нет).
const Words = struct {
    buf: []const u8,
    pos: usize = 0,

    fn next(self: *Words) ?[]const u8 {
        while (self.pos < self.buf.len and isSep(self.buf[self.pos])) self.pos += 1;
        if (self.pos >= self.buf.len) return null;
        const start = self.pos;
        while (self.pos < self.buf.len and !isSep(self.buf[self.pos])) self.pos += 1;
        return self.buf[start..self.pos];
    }
};

/// Порог нечёткого совпадения: max(1, query_codepoints / 3)
/// («превет»→«привет» находит, более дальние опечатки — нет).
fn fuzzyThreshold(query_cp: usize) u16 {
    return @intCast(@max(@as(usize, 1), @divTrunc(query_cp, 3)));
}

/// Query из одного слова (без разделителей) — только для него fuzzy.
fn isSingleWord(query: []const u8) bool {
    for (query) |b| {
        if (isSep(b)) return false;
    }
    return true;
}

/// Максимум codepoint'ов на сторону (тела ≤ 4096 байт ⇒ ≤ 4096 cp).
const max_cp = 4096;

/// Декодирование со свёрткой в out; null — больше max_cp codepoint'ов.
fn foldCps(buf: []const u8, out: *[max_cp]u21) ?usize {
    var i: usize = 0;
    var n: usize = 0;
    while (i < buf.len) {
        const c = nextCp(buf, i);
        i += c.len;
        if (n >= out.len) return null;
        out[n] = foldCp(c.cp);
        n += 1;
    }
    return n;
}

/// Регистронезависимый Левенштейн по codepoint'ам: расстояние ≤ limit?
/// Катящаяся DP-строка с досрочным выходом (минимум строки > limit).
/// Стек ≈ 48 КБ (буферы фиксированы, тел ≤ 4096 байт).
fn levFoldWithin(a: []const u8, b: []const u8, limit: u16) bool {
    var ab: [max_cp]u21 = undefined;
    var bb: [max_cp]u21 = undefined;
    const la = foldCps(a, &ab) orelse return false;
    const lb = foldCps(b, &bb) orelse return false;
    // нижняя граница расстояния — разница длин
    const diff: u32 = @intCast(if (la > lb) la - lb else lb - la);
    if (diff > limit) return false;
    if (la == 0 or lb == 0) return true;
    var prev: [max_cp + 1]u16 = undefined;
    var cur: [max_cp + 1]u16 = undefined;
    for (0..lb + 1) |j| prev[j] = @intCast(j);
    for (ab[0..la], 0..) |ca, i| {
        cur[0] = @intCast(i + 1);
        var row_min: u16 = cur[0];
        for (bb[0..lb], 0..) |cb, j| {
            const cost: u16 = if (ca == cb) 0 else 1;
            var v: u16 = prev[j] + cost; // замена/совпадение
            const del_b = prev[j + 1] + 1; // удаление b-символа
            if (del_b < v) v = del_b;
            const ins_b = cur[j] + 1; // вставка b-символа
            if (ins_b < v) v = ins_b;
            cur[j + 1] = v;
            if (v < row_min) row_min = v;
        }
        if (row_min > limit) return false;
        @memcpy(prev[0 .. lb + 1], cur[0 .. lb + 1]);
    }
    return prev[lb] <= limit;
}

/// Классификация записи: точная подстрока / нечёткое слово / мимо.
/// Точное всегда побеждает нечёткое (запись «привет превет» на query
/// «привет» — exact, бит2 = 0).
const Match = enum { none, exact, fuzzy };

fn classify(body: []const u8, query: []const u8, query_cp: usize) Match {
    if (containsFold(body, query)) return .exact;
    if (!isSingleWord(query)) return .none;
    const limit = fuzzyThreshold(query_cp);
    var it = Words{ .buf = body };
    while (it.next()) |word| {
        if (levFoldWithin(word, query, limit)) return .fuzzy;
    }
    return .none;
}

// ------------------------------------------------------------------- ответ

/// Собрать ответ SEARCH_MESSAGE / GLOBAL_SEARCH_MESSAGE по записям.
/// args — уже валидированные (validate); recs — разобранные записи
/// (Rec). Записи ответа: сначала точные совпадения (новые → старые),
/// затем нечёткие (новые → старые); offset/limit режут объединённый
/// список; budget — лимит payload (прод: api.max_payload = 16 MiB; запись, не
/// влезающая в бюджет, завершает список — count < limit).
/// global (args.cid == null): каждая запись начинается с [cid u32].
/// Аллокации (классификация + индексы окна) освобождаются до возврата.
pub fn writeResponse(alloc: std.mem.Allocator, w: *api.Writer, recs: []const Rec, args: Args, budget: usize) api.Status {
    const global = args.cid == null;
    // фаза 1: классификация записей, подсчёт совпадений
    const kinds = alloc.alloc(Match, recs.len) catch return .INTERNAL;
    defer alloc.free(kinds);
    const query_cp = cpLen(args.query);
    var exact_total: usize = 0;
    var fuzzy_total: usize = 0;
    for (recs, 0..) |rec, i| {
        if (args.cid) |cid| {
            if (rec.cid != cid) {
                kinds[i] = .none;
                continue;
            }
        }
        const m = classify(rec.body, args.query, query_cp);
        kinds[i] = m;
        switch (m) {
            .exact => exact_total += 1,
            .fuzzy => fuzzy_total += 1,
            .none => {},
        }
    }
    // фаза 2: окно [offset, offset+limit) поверх объединённого списка
    // — сначала точные (новые → старые), затем нечёткие (новые →
    // старые): два прохода по записям. Внутри группы позиции монотонны,
    // выход за окно — выход из прохода. Первая запись поверх бюджета
    // завершает список (count < limit).
    var out_idx: std.ArrayListUnmanaged(usize) = .empty;
    defer out_idx.deinit(alloc);
    var budget_left: usize = if (budget > 8) budget - 8 else 0;
    const window_end: u64 = @as(u64, args.offset) + @as(u64, args.limit);
    var kind: Match = .exact;
    while (true) {
        var pos: usize = if (kind == .exact) 0 else exact_total;
        var i: usize = recs.len;
        while (i > 0) {
            i -= 1;
            if (kinds[i] != kind) continue;
            const p = pos;
            pos += 1;
            if (p >= window_end) break; // позиции в группе монотонны
            if (p < args.offset) continue;
            var size = recs[i].size;
            if (global) size += 4; // [cid u32]
            if (size > budget_left) break;
            out_idx.append(alloc, i) catch return .INTERNAL;
            budget_left -= size;
        }
        if (kind == .exact) kind = .fuzzy else break;
    }
    // запись ответа: [total][count] × {record}
    w.putU32(@intCast(exact_total + fuzzy_total)) catch return .INTERNAL;
    w.putU32(@intCast(out_idx.items.len)) catch return .INTERNAL;
    for (out_idx.items) |ri| {
        const rec = recs[ri];
        if (global) w.putU32(rec.cid) catch return .INTERNAL;
        var flags = rec.flags;
        if (kinds[ri] == .fuzzy) flags |= flag_fuzzy;
        w.putU8(flags) catch return .INTERNAL;
        w.putBytes(&rec.msg_id) catch return .INTERNAL;
        w.putU64(rec.ts_ms) catch return .INTERNAL;
        w.putStr16(rec.body) catch return .INTERNAL;
        w.putBytes(rec.tail) catch return .INTERNAL;
    }
    return .OK;
}

// ------------------------------------------------------------------- тесты

const testing = std.testing;

test "parseArgs: оба формата, BAD_FRAME на обрезку и хвост" {
    var w = api.Writer.init(testing.allocator);
    defer w.deinit();
    // контактный формат: [cid][query][limit][offset]
    try w.putU32(7);
    try w.putStr16("привет");
    try w.putU32(0);
    try w.putU32(12);
    const a = parseArgs(w.items(), false) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 7), a.cid.?);
    try testing.expectEqualStrings("привет", a.query);
    try testing.expectEqual(@as(u32, 0), a.limit);
    try testing.expectEqual(@as(u32, 12), a.offset);
    // тот же payload глобальным парсером: cid съедает str16-длину,
    // дальше мусор → null
    try testing.expect(parseArgs(w.items(), true) == null);

    // глобальный формат: [query][limit][offset]
    var g = api.Writer.init(testing.allocator);
    defer g.deinit();
    try g.putStr16("query");
    try g.putU32(50);
    try g.putU32(3);
    const ga = parseArgs(g.items(), true) orelse return error.TestUnexpectedResult;
    try testing.expect(ga.cid == null);
    try testing.expectEqualStrings("query", ga.query);
    try testing.expectEqual(@as(u32, 50), ga.limit);
    // контактный парсер глобального payload → null (структура другая)
    try testing.expect(parseArgs(g.items(), false) == null);

    // обрезка и лишние байты
    try testing.expect(parseArgs(&[_]u8{ 1, 2, 3 }, false) == null);
    try testing.expect(parseArgs(&[_]u8{ 1, 2, 3 }, true) == null);
    const extra = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99 };
    try testing.expect(parseArgs(&extra, true) == null);
}

test "validate: нормализация limit и все ветки ошибок" {
    var a = Args{ .cid = 1, .query = "q", .limit = 0, .offset = 0 };
    try testing.expect(validate(&a) == null);
    try testing.expectEqual(@as(u32, 50), a.limit);
    a.limit = 200;
    try testing.expect(validate(&a) == null);
    a.limit = 201;
    try testing.expectEqual(api.Status.TOO_BIG, validate(&a).?);
    a.limit = 50;
    a.query = "";
    try testing.expectEqual(api.Status.BAD_ARGS, validate(&a).?);
    var long: [4097]u8 = @splat('x');
    a.query = &long;
    try testing.expectEqual(api.Status.TOO_BIG, validate(&a).?);
}

test "containsFold: ASCII, кириллица, Ё/ё, некорректный UTF-8" {
    try testing.expect(containsFold("КотоВода", "кот"));
    try testing.expect(containsFold("ёлка", "ЁЛКА"));
    try testing.expect(containsFold("hello WORLD", "Hello world"));
    try testing.expect(!containsFold("hello", "привет"));
    try testing.expect(!containsFold("кот", "кото"));
    // фраза с пробелами
    try testing.expect(containsFold("Как ДЕЛА, друг", "как дела"));
    // некорректный UTF-8 в теле: сырой байт = codepoint, матч не роняется
    try testing.expect(containsFold("ab\xFFcd", "ab"));
    try testing.expect(containsFold("ab\xFFcd", "\xFF"));
}

test "classify: точное, нечёткое, приоритет, порог, многословный query" {
    // точное (регистронезависимая подстрока)
    try testing.expectEqual(Match.exact, classify("Привет, как дела", "привет", 6));
    try testing.expectEqual(Match.exact, classify("приветик!", "привет", 6));
    // нечёткое: «превет»/«привет» dist 1 ≤ 2; «прывет» dist 2 ≤ 2;
    // «совсем» — ни одного общего символа, мимо
    try testing.expectEqual(Match.fuzzy, classify("он написал превет и ушёл", "привет", 6));
    try testing.expectEqual(Match.fuzzy, classify("ответ: прывет!", "привет", 6));
    try testing.expectEqual(Match.none, classify("совсем", "привет", 6));
    // ASCII: hello 5 cp → порог 1; «helo» dist 1, «helxx» dist 2
    try testing.expectEqual(Match.fuzzy, classify("helo world", "hello", 5));
    try testing.expectEqual(Match.none, classify("helxx world", "hello", 5));
    // короткий query: abc 3 cp → порог 1
    try testing.expectEqual(Match.fuzzy, classify("abd", "abc", 3));
    try testing.expectEqual(Match.none, classify("xyz", "abc", 3));
    // точное побеждает нечёткое
    try testing.expectEqual(Match.exact, classify("привет и превет рядом", "привет", 6));
    // многословный query — только точная подстрока, fuzzy выключен
    try testing.expectEqual(Match.exact, classify("как дела", "как дела", 7));
    try testing.expectEqual(Match.none, classify("кок дола", "как дела", 7));
    // регистронезависимость нечёткого: «ПРЕВЕТ» матчится
    try testing.expectEqual(Match.fuzzy, classify("ПРЕВЕТ", "привет", 6));
}

/// Макет Rec: хвост = счётчик 0, msg_id = байт-заполнитель.
fn mkRec(cid: u32, mine: bool, id: u8, ts: u64, body: []const u8) Rec {
    return .{
        .cid = cid,
        .flags = @intFromBool(mine),
        .msg_id = @splat(id),
        .ts_ms = ts,
        .body = body,
        .tail = &zero_tail,
        .size = 1 + 16 + 8 + 2 + body.len + 1,
    };
}

test "writeResponse: контактный поиск — порядок, флаги, offset/limit" {
    const recs = [_]Rec{
        mkRec(1, true, 0xAA, 100, "ПРивет друг"), // exact, старая
        mkRec(1, false, 0xBB, 200, "погода хорошая"), // мимо
        mkRec(1, true, 0xCC, 300, "написал превет вчера"), // fuzzy
        mkRec(1, false, 0xDD, 400, "приветик!"), // exact, новая
        mkRec(1, true, 0xEE, 500, "ПРЕВЕТ"), // fuzzy, новая
        mkRec(2, true, 0xFF, 600, "привет чужой чат"), // чужой cid
    };

    var w = api.Writer.init(testing.allocator);
    defer w.deinit();
    const st = writeResponse(testing.allocator, &w, &recs, .{ .cid = 1, .query = "привет", .limit = 50, .offset = 0 }, api.max_payload);
    try testing.expectEqual(api.Status.OK, st);

    // точные новые → старые, затем нечёткие новые → старые;
    // total = 4 (2 exact + 2 fuzzy), count = 4
    var r = api.Reader.init(w.items());
    try testing.expectEqual(@as(u32, 4), try r.readU32());
    try testing.expectEqual(@as(u32, 4), try r.readU32());
    // 1: приветик! (exact, новая)
    try testing.expectEqual(@as(u8, 0), try r.readU8()); // flags: not mine, not fuzzy
    const mid1 = try r.readBytes(16);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0xDD)), mid1);
    try testing.expectEqual(@as(u64, 400), try r.readU64());
    try testing.expectEqualStrings("приветик!", try r.readStr16());
    try testing.expectEqual(@as(u8, 0), (try r.readBytes(1))[0]); // хвост: счётчик 0
    // 2: ПРивет друг (exact, старая; тело в оригинальном регистре)
    try testing.expectEqual(@as(u8, 1), try r.readU8()); // mine
    _ = try r.readBytes(16);
    try testing.expectEqual(@as(u64, 100), try r.readU64());
    try testing.expectEqualStrings("ПРивет друг", try r.readStr16());
    _ = try r.readBytes(1);
    // 3: ПРЕВЕТ (fuzzy, новая)
    try testing.expectEqual(@as(u8, 1 | flag_fuzzy), try r.readU8());
    _ = try r.readBytes(16);
    try testing.expectEqual(@as(u64, 500), try r.readU64());
    try testing.expectEqualStrings("ПРЕВЕТ", try r.readStr16());
    _ = try r.readBytes(1);
    // 4: написал превет вчера (fuzzy, старая)
    try testing.expectEqual(@as(u8, 1 | flag_fuzzy), try r.readU8());
    _ = try r.readBytes(16);
    try testing.expectEqual(@as(u64, 300), try r.readU64());
    try testing.expectEqualStrings("написал превет вчера", try r.readStr16());
    _ = try r.readBytes(1);
    try testing.expect(!r.hasMore());

    // offset/limit: окно через границу сегментов
    var w2 = api.Writer.init(testing.allocator);
    defer w2.deinit();
    _ = try testing.expectEqual(api.Status.OK, writeResponse(testing.allocator, &w2, &recs, .{ .cid = 1, .query = "привет", .limit = 2, .offset = 1 }, api.max_payload));
    var r2 = api.Reader.init(w2.items());
    try testing.expectEqual(@as(u32, 4), try r2.readU32());
    try testing.expectEqual(@as(u32, 2), try r2.readU32());
    // окно [1, 3): «ПРивет друг» (exact, позиция 1) и «ПРЕВЕТ» (fuzzy, 2)
    try testing.expectEqual(@as(u8, 1), try r2.readU8()); // mine, не fuzzy
    _ = try r2.readBytes(16);
    try testing.expectEqual(@as(u64, 100), try r2.readU64());
    try testing.expectEqualStrings("ПРивет друг", try r2.readStr16());
    _ = try r2.readBytes(1);
    try testing.expectEqual(@as(u8, 1 | flag_fuzzy), try r2.readU8());
    _ = try r2.readBytes(16);
    try testing.expectEqual(@as(u64, 500), try r2.readU64());
    try testing.expectEqualStrings("ПРЕВЕТ", try r2.readStr16());
    _ = try r2.readBytes(1);
    try testing.expect(!r2.hasMore());

    // offset за пределами total — пустой список
    var w3 = api.Writer.init(testing.allocator);
    defer w3.deinit();
    _ = try testing.expectEqual(api.Status.OK, writeResponse(testing.allocator, &w3, &recs, .{ .cid = 1, .query = "привет", .limit = 50, .offset = 10 }, api.max_payload));
    var r3 = api.Reader.init(w3.items());
    try testing.expectEqual(@as(u32, 4), try r3.readU32());
    try testing.expectEqual(@as(u32, 0), try r3.readU32());
    try testing.expect(!r3.hasMore());
}

test "writeResponse: бюджет режет count, total остаётся полным" {
    const recs = [_]Rec{
        mkRec(1, true, 1, 100, "привет раз"),
        mkRec(1, true, 2, 200, "привет два"),
        mkRec(1, true, 3, 300, "привет три"),
    };
    // размер записи: 1+16+8+2+19+1 = 47 («привет раз» — 19 байт UTF-8);
    // бюджет 8+47 — влезает ровно одна
    var w = api.Writer.init(testing.allocator);
    defer w.deinit();
    _ = try testing.expectEqual(api.Status.OK, writeResponse(testing.allocator, &w, &recs, .{ .cid = 1, .query = "привет", .limit = 50, .offset = 0 }, 8 + 47));
    var r = api.Reader.init(w.items());
    try testing.expectEqual(@as(u32, 3), try r.readU32());
    try testing.expectEqual(@as(u32, 1), try r.readU32());
    _ = try r.readU8();
    _ = try r.readBytes(16);
    try testing.expectEqual(@as(u64, 300), try r.readU64()); // самая новая
    try testing.expectEqualStrings("привет три", try r.readStr16());
    _ = try r.readBytes(1);
    try testing.expect(!r.hasMore());
    // нулевой бюджет — только заголовок
    var w2 = api.Writer.init(testing.allocator);
    defer w2.deinit();
    _ = try testing.expectEqual(api.Status.OK, writeResponse(testing.allocator, &w2, &recs, .{ .cid = 1, .query = "привет", .limit = 50, .offset = 0 }, 0));
    var r2 = api.Reader.init(w2.items());
    try testing.expectEqual(@as(u32, 3), try r2.readU32());
    try testing.expectEqual(@as(u32, 0), try r2.readU32());
}

test "writeResponse: глобальный поиск — записи несут cid, все чаты" {
    const recs = [_]Rec{
        mkRec(1, false, 0x11, 100, "привет из первого"),
        mkRec(3, true, 0x22, 200, "привет из третьего"),
        mkRec(2, false, 0x33, 300, "превет опечатка"),
    };

    var w = api.Writer.init(testing.allocator);
    defer w.deinit();
    _ = try testing.expectEqual(api.Status.OK, writeResponse(testing.allocator, &w, &recs, .{ .cid = null, .query = "привет", .limit = 50, .offset = 0 }, api.max_payload));
    var r = api.Reader.init(w.items());
    try testing.expectEqual(@as(u32, 3), try r.readU32()); // 2 exact + 1 fuzzy
    try testing.expectEqual(@as(u32, 3), try r.readU32());
    // точные раньше: свежий exact «привет из третьего» (cid 3, ts 200),
    // затем «привет из первого» (cid 1), затем fuzzy «превет опечатка»
    // (cid 2, ts 300)
    try testing.expectEqual(@as(u32, 3), try r.readU32());
    try testing.expectEqual(@as(u8, 1), try r.readU8()); // mine
    _ = try r.readBytes(16);
    try testing.expectEqual(@as(u64, 200), try r.readU64());
    try testing.expectEqualStrings("привет из третьего", try r.readStr16());
    _ = try r.readBytes(1);
    try testing.expectEqual(@as(u32, 1), try r.readU32());
    try testing.expectEqual(@as(u8, 0), try r.readU8());
    _ = try r.readBytes(16);
    try testing.expectEqual(@as(u64, 100), try r.readU64());
    try testing.expectEqualStrings("привет из первого", try r.readStr16());
    _ = try r.readBytes(1);
    try testing.expectEqual(@as(u32, 2), try r.readU32());
    try testing.expectEqual(@as(u8, flag_fuzzy), try r.readU8());
    _ = try r.readBytes(16);
    try testing.expectEqual(@as(u64, 300), try r.readU64());
    try testing.expectEqualStrings("превет опечатка", try r.readStr16());
    _ = try r.readBytes(1);
    try testing.expect(!r.hasMore());
}
