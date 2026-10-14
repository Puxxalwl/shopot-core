# Contributing (zig core)

- Требования: Zig 0.17.0. Сборка: `cd zig && zig build -Doptimize=ReleaseFast`.
- Тесты: `zig build test`. Всё зелёное — только потом PR/коммит.
- Правила разработки и агентские правила: AGENTS.md.
- Криптография и протокол: docs/PROTOCOL.md. Менять формат можно только через
  новый version byte и запись в CHANGELOG.
- Запрещено: OS-пакеты как зависимость (пользователь ставит только Zig), JSON на проводе, `catch unreachable` вне тестов,
  аллокации на горячем пути без обоснования в комментарии.
