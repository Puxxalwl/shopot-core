//! Presence: пассивный heartbeat с миллисекундными метками.
//! Чистая машина состояний: никаких таймеров/потоков внутри — время (now_ms)
//! даёт вызывающий, например через core.interfaces.Clock.
const std = @import("std");

/// Одно действие тика для вызывающего.
pub const HeartbeatAction = union(enum) {
    /// Делать ничего не нужно.
    none,
    /// Настало время пинга: отправить {seq, ts_ms} и ждать onPong(seq).
    send_ping: struct {
        seq: u32,
        ts_ms: i64,
    },
    /// misses_to_offline пингов подряд остались без понга — peer offline.
    mark_offline,
};

/// Состояние presence. Без аллокаций и побочных эффектов.
pub const State = struct {
    /// Номинальный интервал между пингами.
    interval_ms: i64 = 5000,
    /// Тишина от peer, после которой начинаем пинговать.
    idle_after_ms: i64 = 4000,
    /// Сколько пингов подряд без понга переводят peer в offline.
    misses_to_offline: u8 = 3,
    /// Последнее входящее событие от peer.
    last_seen_ms: i64 = 0,
    /// Последний отправленный пинг.
    last_sent_ms: i64 = 0,
    /// Монотонный номер последнего отправленного пинга (детерминирован).
    seq: u32 = 0,
    /// Пинги подряд без понга.
    missed: u8 = 0,
    /// Peer считается на связи.
    online: bool = false,

    /// Входящее событие от peer: мгновенно online (на метку now_ms), тишина и
    /// пропуски сброшены.
    pub fn onInbound(self: *State, now_ms: i64) void {
        self.last_seen_ms = now_ms;
        self.missed = 0;
        self.online = true;
    }

    /// Понг гасит ожидание ответа. Поздние понги (seq старее последнего
    /// отправленного) игнорируются. Время не двигает last_seen: живость данных
    /// учитывается через onInbound.
    pub fn onPong(self: *State, seq: u32, now_ms: i64) void {
        _ = now_ms;
        if (seq == self.seq) self.missed = 0;
    }

    /// Тик присутствия. Пинг ТОЛЬКО если тишина (now - last_seen >= idle_after)
    /// И интервал истёк (now - last_sent >= interval). Когда misses_to_offline
    /// пингов подряд остались без понга — ровно один mark_offline; до первого
    /// onInbound (и после offline) тики молчат.
    pub fn tick(self: *State, now_ms: i64) HeartbeatAction {
        if (!self.online) return .none;
        const idle = now_ms - self.last_seen_ms >= self.idle_after_ms;
        // Пропавший peer опрашивается всё реже: 5с -> 10 -> 20 -> 40 -> 60(кап).
        // Пока идёт трафик — пингов нет вообще (idle_after не истёк).
        const shift: u6 = @intCast(@min(self.missed -| 1, 4));
        const eff = @min(self.interval_ms << shift, 60_000);
        const due = now_ms - self.last_sent_ms >= eff;
        if (!idle or !due) return .none;
        if (self.missed >= self.misses_to_offline) {
            self.online = false; // ровно один mark_offline: дальше тики молчат
            return .mark_offline;
        }
        self.seq +%= 1;
        self.last_sent_ms = now_ms;
        self.missed += 1;
        return .{ .send_ping = .{ .seq = self.seq, .ts_ms = now_ms } };
    }
};

test "heartbeat: inbound делает online мгновенно, до установления тики молчат" {
    const testing = std.testing;
    var s = State{};
    try testing.expect(!s.online);
    try testing.expect(s.tick(1_000) == .none);
    s.onInbound(1_000);
    try testing.expect(s.online);
    try testing.expect(s.tick(1_000) == .none); // тишина 0 < idle_after
}

test "heartbeat: миллисекундная точность границ idle и interval" {
    const testing = std.testing;
    var s = State{ .interval_ms = 100, .idle_after_ms = 4_000 };
    s.onInbound(0);
    try testing.expect(s.tick(3_999) == .none); // тишина 3999 < 4000
    const a1 = s.tick(4_000); // тишина ровно 4000, интервал истёк
    try testing.expect(a1 == .send_ping);
    try testing.expectEqual(@as(u32, 1), a1.send_ping.seq);
    try testing.expectEqual(@as(i64, 4_000), a1.send_ping.ts_ms);
    try testing.expect(s.tick(4_099) == .none); // интервал 99 < 100
    const a2 = s.tick(4_100);
    try testing.expect(a2 == .send_ping);
    try testing.expectEqual(@as(u32, 2), a2.send_ping.seq);
}

test "heartbeat: при активном трафике пингов нет" {
    const testing = std.testing;
    var s = State{};
    var t: i64 = 0;
    while (t < 60_000) : (t += 100) {
        s.onInbound(t);
        try testing.expect(s.tick(t) == .none);
    }
    try testing.expect(s.online);
}

test "heartbeat: offline ровно после 3 пропусков, один раз" {
    const testing = std.testing;
    var s = State{};
    s.onInbound(0);
    const a1 = s.tick(5_000);
    const a2 = s.tick(10_000);
    const a3 = s.tick(15_000);
    try testing.expect(a1 == .send_ping and a1.send_ping.seq == 1);
    try testing.expect(a2 == .send_ping and a2.send_ping.seq == 2);
    try testing.expect(a3 == .send_ping and a3.send_ping.seq == 3);
    try testing.expectEqual(@as(u8, 3), s.missed); // три пинга подряд без понга
    try testing.expect(s.online);
    const off = s.tick(20_000);
    try testing.expect(off == .mark_offline);
    try testing.expect(!s.online);
    try testing.expect(s.tick(25_000) == .none);
    try testing.expect(s.tick(30_000) == .none);
    try testing.expectEqual(@as(u32, 3), s.seq); // seq больше не растёт
}

test "heartbeat: pong гасит ожидание, поздний игнорируется, inbound возрождает" {
    const testing = std.testing;
    var s = State{};
    s.onInbound(0);
    var t: i64 = 5_000;
    var expect_seq: u32 = 1;
    while (expect_seq <= 10) : (expect_seq += 1) {
        const a = s.tick(t);
        try testing.expect(a == .send_ping and a.send_ping.seq == expect_seq);
        s.onPong(expect_seq, t + 50);
        try testing.expectEqual(@as(u8, 0), s.missed);
        try testing.expect(s.online);
        t += 5_000;
    }
    // поздний понг (seq старее последнего отправленного) не гасит ожидание
    _ = s.tick(t);
    const seq_now = s.seq;
    s.onPong(seq_now - 1, t + 10);
    try testing.expectEqual(@as(u8, 1), s.missed);

    // возобновление presence после offline
    s = State{};
    s.onInbound(0);
    _ = s.tick(5_000);
    _ = s.tick(10_000);
    _ = s.tick(15_000);
    try testing.expect(s.tick(20_000) == .mark_offline);
    s.onInbound(20_500);
    try testing.expect(s.online and s.missed == 0);
    try testing.expect(s.tick(20_500) == .none);
}

test "heartbeat: seq детерминирован на одинаковых таймлайнах" {
    const testing = std.testing;
    const trace = struct {
        fn run() ![12]i64 {
            var s = State{};
            var out: [12]i64 = undefined;
            s.onInbound(100);
            var t: i64 = 100;
            for (&out) |*o| {
                switch (s.tick(t)) {
                    .none => o.* = -1,
                    .send_ping => |p| o.* = p.seq,
                    .mark_offline => o.* = -2,
                }
                t += 1_000;
            }
            return out;
        }
    };
    const t1 = try trace.run();
    const t2 = try trace.run();
    try testing.expectEqualSlices(i64, &t1, &t2);
}
