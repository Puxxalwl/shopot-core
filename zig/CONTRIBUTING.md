# Contributing (zig core)

Contribution rules (kernel-style: commit format, checklist, sign-off, review
process) live in the repository root:
[CONTRIBUTING.md](../CONTRIBUTING.md) /
[CONTRIBUTING.ru.md](../CONTRIBUTING.ru.md).

Local reminders for the `zig/` tree:

- Toolchain: Zig 0.17.0. Build: `cd zig && zig build -Doptimize=ReleaseFast`.
- Tests: `zig build test`. All green — only then PR/commit.
- Coding and agent rules: [AGENTS.md](AGENTS.md).
- Cryptography and wire format: [docs/PROTOCOL.md](docs/PROTOCOL.md).
  The format changes only through a new version byte and a CHANGELOG entry.
- Forbidden: OS packages as dependencies (the user installs only Zig), JSON
  on any wire, `catch unreachable` outside tests, hot-path allocations
  without a justifying comment.
