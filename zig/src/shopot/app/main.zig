//! shopot-zig CLI: thin REPL over the core. std-only.
const std = @import("std");
const shopot = @import("shopot");

const usage =
    \\shopot-zig — encrypted messenger core (std-only Zig)
    \\
    \\  init                     generate identity seed (~/.shopot/zig-seed, 0600)
    \\  id                       print your bundle and fingerprint
;

fn loadSeed(io: std.Io, home: []const u8) ![32]u8 {
    if (home.len == 0) return error.NoHome;
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/.shopot/zig-seed", .{home});
    const f = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_only });
    defer f.close(io);
    var seed: [32]u8 = undefined;
    const n = try f.readPositionalAll(io, &seed, 0);
    if (n != 32) return error.BadSeed;
    return seed;
}

fn saveSeed(io: std.Io, home: []const u8, seed: [32]u8) !void {
    if (home.len == 0) return error.NoHome;
    var path_buf: [512]u8 = undefined;
    std.Io.Dir.createDirAbsolute(io, try std.fmt.bufPrint(&path_buf, "{s}/.shopot", .{home}), .default_dir) catch {};
    const path = try std.fmt.bufPrint(&path_buf, "{s}/.shopot/zig-seed", .{home});
    const f = try std.Io.Dir.createFileAbsolute(io, path, .{ .exclusive = true });
    defer f.close(io);
    try f.writePositionalAll(io, &seed, 0);
    f.setPermissions(io, .fromMode(0o600)) catch {};
}

pub fn main(start: std.process.Init) !void {
    const io = start.io;
    const home: []const u8 = start.environ_map.get("HOME") orelse "";
    const argv = start.minimal.args.vector;

    if (argv.len < 2) {
        std.debug.print("{s}\n", .{usage});
        return;
    }
    const cmd: []const u8 = std.mem.span(argv[1]);

    if (std.mem.eql(u8, cmd, "init")) {
        var seed: [32]u8 = undefined;
        io.random(&seed);
        try saveSeed(io, home, seed);
        var id = try shopot.crypto.identity.Identity.fromSeed(seed);
        defer id.deinit();
        var fp_buf: [96]u8 = undefined;
        std.debug.print("identity created, seed saved to ~/.shopot/zig-seed (0600)\nfingerprint: {s}\n", .{try id.fingerprintTo(&fp_buf)});
        return;
    }

    if (std.mem.eql(u8, cmd, "id")) {
        const seed = try loadSeed(io, home);
        var id = try shopot.crypto.identity.Identity.fromSeed(seed);
        defer id.deinit();
        const bundle = id.bundle();
        var hex_buf: [130]u8 = undefined;
        var n: usize = 0;
        for (bundle) |byte| {
            const printed = try std.fmt.bufPrint(hex_buf[n..], "{x:0>2}", .{byte});
            n += printed.len;
        }
        var fp_buf: [96]u8 = undefined;
        std.debug.print("bundle(hex): {s}\nfingerprint: {s}\n", .{ hex_buf[0..n], try id.fingerprintTo(&fp_buf) });
        return;
    }

    std.debug.print("{s}\n", .{usage});
}
