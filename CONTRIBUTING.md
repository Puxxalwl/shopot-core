# Contributing to shopot-core

**English** | [Русский](docs/ru/CONTRIBUTING.md)

Contribution rules are modeled on the Linux kernel process
([submitting-patches](https://docs.kernel.org/process/submitting-patches.html),
[submit-checklist](https://kernel.org/doc/html/latest/process/submit-checklist.html)),
adapted to a Zig project on GitHub. Read this before opening a PR.

## 1. Ground rules (invariants — violations are rejected)

- **No servers, no telemetry, no third-party calls** in the core. A relay is
  user-hosted software, not a service; LAN discovery is local. Nothing in the
  core may require infrastructure.
- **std-only.** No OS packages (`pacman`/`apt`/`brew`): the user installs
  nothing but Zig. Zig packages (build.zig.zon, hash-pinned) are possible but
  each dependency needs a justification in CHANGELOG.md; the crypto core
  stays on `std.crypto`.
- **Plaintext never reaches the disk layer.** Any code path that persists
  user content goes through the sealed log. Tests must keep proving at-rest
  encryption.
- **No JSON on any wire.** Both protocols (P2P and UDS) are binary, LE,
  fixed-width fields, no varint. Incompatible changes require a version-byte
  bump, never a silent field redefinition.
- **No new crypto primitives.** Composition of std.crypto only; keys are
  wiped with `std.crypto.secureZero` when their owner dies.

## 2. Development setup

```bash
git clone https://github.com/Puxxalwl/shopot-core.git
cd shopot-core
make test                 # zig build test --summary all
make                      # zig build -Doptimize=ReleaseFast
```

Toolchain: [Zig 0.17.0](https://ziglang.org/download/) — the only
requirement. CI runs the same `zig build test` plus release builds on every
`zig-v*` tag.

Coding rules for the `zig/` tree (allocator discipline, error sets, module
boundaries): [zig/AGENTS.md](zig/AGENTS.md). It binds contributors and
agents equally.

## 3. Source layout and ownership

| Subsystem | Files |
|---|---|
| build/integration | `build.zig`, `src/shopot.zig`, `src/shopot/core/*`, `src/shopot/app/*`, `docs/*`, `CHANGELOG.md` |
| crypto | `src/shopot/crypto/*.zig` |
| proto | `src/shopot/proto/*.zig` |
| net | `src/shopot/net/*.zig` |
| store | `src/shopot/store/*.zig` |

A change touches the files of its subsystem; other subsystems are read-only
for the author of the change (integration is done by the maintainer of the
root scope). A module imports only `core/interfaces.zig`, never a sibling.
Unit tests belong to the module owner; integration scenarios are written
with the integration change.

## 4. Commit messages

Same rules as the kernel, adapted:

- **One logical change per commit.** If a commit does two things, split it.
  Every commit must build and pass `zig build test` on its own
  (bisectability).
- **Subject line**: `subsystem: imperative summary`, ≤ 72 characters, no
  trailing period. Existing prefixes: `zig`, `zig: crypto`, `zig: net`,
  `zig: proto`, `zig: store`, `zig: app`, `zig: core`, `docs`.
  If the change fixes a regression, reference the commit that introduced it
  (`Fixes: <12-hex>` analog in the body).
- **Body**: wrapped at 72 columns. Describe **what** the change does and
  **why** it is needed — motivation, threat-model impact for anything
  touching crypto, storage or signaling. Line-by-line "how" narration is
  noise; the diff already says it.
- **State how you tested it** (unit tests added, integration scenario, E2E
  run). "It works on my machine" is not a test statement.
- **Crypto/protocol changes** additionally require: an update to
  `zig/docs/PROTOCOL.md`, a CHANGELOG.md entry, and the rationale in the
  commit body.
- Never mix whitespace/formatting churn with functional changes; put
  `zig fmt`-only cleanups in their own commit (or, better, avoid them).
- Sign every commit:

```
Signed-off-by: Random J Developer <random@developer.example.org>
```

  The sign-off certifies the [Developer Certificate of Origin
  (DCO)](https://developercertificate.org/): you wrote the contribution
  yourself or have the right to submit it.

### Examples

Good:

```
zig: crypto: derive sealed-frame AD from the full header

The AEAD box was bound to the counter only, so a byte-swap of the
length prefix produced a valid frame the receiver would parse
incorrectly. Bind AD to [wirelen u16][seq u64] as obfuscate.zig
already does on the write path.

Fixes regression introduced in 7b60347.

Tested: unit (header roundtrip + tamper), integration E2E 48 msgs.
```

Bad (reject on sight): `fix`, `wip`, `update files`, subject > 72 chars,
mixed fmt+logic, no body, no sign-off.

## 5. Patch/PR checklist

Adapted from the kernel submission checklist; check every line:

- [ ] `zig fmt` produces no diff (`zig fmt --check .`).
- [ ] `zig build test` is green.
- [ ] New behavior has new tests; a bug fix contains the failing case first.
- [ ] No `catch unreachable` outside tests; no `anyerror` at module
      boundaries; module error sets only.
- [ ] Public functions take `std.mem.Allocator`; no allocations on the hot
      path without a comment justifying them.
- [ ] No new dependencies — or a CHANGELOG justification and maintainer
      discussion first.
- [ ] Wire format touched → version byte decision made explicitly and
      PROTOCOL.md updated.
- [ ] API surface touched → CORE-API.md updated, CHANGELOG entry added.
- [ ] One concern per PR; commit series follows §4.
- [ ] Threat-model impact described for crypto/storage/signaling changes.
- [ ] Docs updated in **both languages** (EN + RU mirror), facts verified
      against source; wire/API change → CHANGELOG entry. See
      [docs/DOCSTYLE.md](docs/DOCSTYLE.md).
- [ ] No regressions: the E2E scenarios in `tests/integration.zig` still
      pass unchanged.

## 6. Review and lifecycle

1. PRs are reviewed against the checklist above. Formatting/argument-order
   fixes may be pushed as follow-ups; invariant violations (§1) close the PR.
2. Review comments are addressed in the same branch, one commit per point or
   a squashed fix with a reference. "Done" without the change is not an
   answer.
3. The maintainer of the root scope performs integration (cross-subsystem
   merges, integration tests, releases tagged `zig-v*`).
4. Anything user-visible lands in CHANGELOG.md at merge time, not later.

## 7. Security issues

Do not open public issues for vulnerabilities. Follow
[SECURITY.md](SECURITY.md) (private GitHub security report; 72 h
acknowledgment target).

## 8. Documentation rules

Documentation follows [docs/DOCSTYLE.md](docs/DOCSTYLE.md) (binding):
EN normative at the canonical path, RU mirror in `ru/` in the same commit,
facts verified against source, contracts in tables, one canonical limits
table per API doc, wire/API changes update PROTOCOL/CORE-API + CHANGELOG in
the same commit. "Docs later" is a reject.

## 9. License

MIT. By contributing you license your work under MIT; the `Signed-off-by`
line (DCO) is the record of that consent.
