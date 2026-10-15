# Documentation rules

**English** | [Русский](ru/DOCSTYLE.md)

Binding rules for writing and changing documentation in shopot-core.
Modeled on how Discord, Telegram, X, WhatsApp document developer contracts
and how the kernel treats documentation as part of the patch. Breaking
these rules is review-blocking, same as code style.

## 1. Layout and languages

- **English is the normative version** and lives at the canonical location:
  `README.md`, `CONTRIBUTING.md`, `SECURITY.md` at the root;
  `zig/docs/X.md` for specifications.
- **Russian mirrors live in `ru/` directories**: `docs/ru/README.md`,
  `docs/ru/CONTRIBUTING.md`, `zig/docs/ru/X.md` — same filename as the
  English original, no `.ru` suffix (the directory carries the language).
- Every doc starts with a language switcher line linking its mirror; both
  directions must work.
- EN and RU must not diverge: a change to one lands in the other **in the
  same commit**. A translation lag is a bug.

## 2. Voice

- Normative and technical. No marketing, no filler, no "simply",
  "easily", "just", no exclamation marks.
- Facts only, present tense, active voice. The docs describe what the code
  does today — wishes belong in ROADMAP.md and are marked as not done.
- Each doc states its audience in the first two lines (client authors /
  contributors / implementers).

## 3. Facts come from code

- Every byte layout, constant, limit, numeric code and path is verified
  against the source before writing it down. No numbers from memory.
- Code and docs disagree → one of them is wrong. Fix both in one commit or
  file it; never document the desired state as the current state.
- A doc never specifies behavior that no implementation has (ROADMAP items
  are the only exception and must be labeled).

## 4. Structure by doc type

- **Specifications** (PROTOCOL, CORE-API): numbered sections with stable
  numbers; never renumber existing sections — append. Byte layouts in
  fenced code blocks; contracts in tables.
- **Machine contracts** (statuses, methods, events, envelope tags): a table
  with numeric value + SCREAMING_SNAKE name + when it occurs. Names are the
  contract; numbers are the wire.
- **One canonical Limits table per API document.** A new limit goes into
  that table, never into prose only.
- **Honest limits**: every security-relevant document has a section on what
  is *not* covered (see PROTOCOL §18).
- **Deliberate deviations** from a referenced external spec are stated
  explicitly with the reason (e.g. the avatar size cap).
- Scenarios/quickstart sections describe flows in terms of the API
  (request → response → event), not prose.

## 5. Notation

- `u8`/`u16`/`u32`/`u64` — unsigned integers of 1/2/4/8 bytes.
  Little-endian is the default; big-endian only when a field says so.
- `[N]` — N raw bytes; `str16`/`str32` = `[len u16|u32][bytes]` (UTF-8, no
  terminator).
- Hexadecimal with `0x` prefix for constants and tags.
- Wrap prose at ≤ 80 columns.
- Status symbols (`✅`, `~~done~~`, `❌`) only in ROADMAP.md.

## 6. Links

- Relative links, resolved against the file's own directory. Run a link
  check over the changed files before committing.
- Cross-language links: EN → `ru/X.md`, RU → `../X.md`.
- Reference sections by number (`§7`), not by title alone.

## 7. Change discipline

- A wire-format or API change requires the matching doc update
  (PROTOCOL.md / CORE-API.md) **and a CHANGELOG.md entry in the same
  commit** — see CONTRIBUTING §1 and §4.
- Version strings inside docs follow the wire protocol / API version; they
  bump together with the code.
- A new document must be registered in the README docs table (both
  languages) and, if it describes process, referenced from CONTRIBUTING.
- Moving or renaming a doc updates every inbound link in the same commit.

## 8. Review

Docs are reviewed with the same checklist as code: link check, both
languages updated, facts verified against source, CHANGELOG entry when a
contract changed. "Docs later" is a reject.
