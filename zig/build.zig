const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("shopot", .{
        .root_source_file = b.path("src/shopot.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "shopot-zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shopot/app/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("shopot", mod);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the CLI");
    run_step.dependOn(&run_cmd.step);

    const unit = b.addTest(.{ .root_module = mod });
    const run_unit = b.addRunArtifact(unit);
    const test_step = b.step("test", "Run module tests");
    test_step.dependOn(&run_unit.step);

    const integ_mod = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    integ_mod.addImport("shopot", mod);
    const integ = b.addTest(.{ .root_module = integ_mod });
    const run_integ = b.addRunArtifact(integ);
    test_step.dependOn(&run_integ.step);
}
