# Contributing

## Setup

```bash
git clone https://github.com/Puxxalwl/shopot-core.git
cd shopot-core
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

System deps: `libsodium`, `sqlite3`, CMake ≥ 3.24, GCC ≥ 12 or Clang ≥ 15.
Everything else is fetched by CMake.

## Ground rules

- **No servers, no telemetry, no third-party calls** in the core. STUN is the
  only permitted external contact and must stay optional.
- **Plaintext never reaches the disk layer.** If a code path writes user
  content, it goes through `Db` sealing. Tests must keep proving at-rest
  encryption (`test_db` greps the raw file for plaintext).
- **No new dependencies without a discussion.** Current set: libsodium,
  sqlite3, nlohmann_json, libdatachannel. Every addition is supply-chain risk.
- Crypto changes require updating `docs/PROTOCOL.md` and a rationale in the
  commit message.

## Style

- C++20, `-Wall -Wextra` clean.
- 2-space indent, snake_case functions, PascalCase types (match the existing
  files).
- Public API stays in the single header `include/shopot/shopot.hpp` and
  must remain source-compatible within a minor version.

## Tests

`tests/test_main.cpp` runs the whole protocol between two in-process parties
over a loopback channel — extend it when you change the wire format. Run
`SHOPOT_LOG=1 ./build/shopot-cli` for verbose transport logs when debugging
connectivity.

## Pull requests

One concern per PR. Describe the threat-model impact for anything touching
crypto, storage or signaling. By contributing you license your work under MIT.
