# shopot

[English](../../README.md) | **Русский**

Ядро серверлесс P2P-мессенджера: **ноль своих серверов**, история сообщений
живёт только на двух устройствах. Реализация — чистый Zig, std-only: без
пакетов и зависимостей от ОС. Исходники: [`zig/`](../../zig/).

C++-версия (v0.2.4, FTXUI/MQTT/WebRTC) удалена из master; архив — тег
`cpp-archive`.

## Возможности

| Область | Что делает ядро |
|---|---|
| Идентичность | пары X25519 + Ed25519, выведенные из одного сида 32 байта (`~/.shopot/zig-seed`, 0600) |
| Транспорт | прямой TCP (порты 7777–7786) или само-хостнутый релей; LAN-обнаружение через UDP-мультикаст; провод замаскирован под TLS 1.3 |
| Шифрование | XX-подобное рукопожатие, AEAD-транспорт, двойной рэтчет с post-compromise security (ротация эпох каждые 256 сообщений) |
| Сообщения | доставка офлайн (шифрованный outbox, ACK, дедуп), реакции, звонки 16 кГц E2EE (ADPCM, DTX), файлы с докачкой |
| Хранилище | append-only AEAD-лог — ноль байт открытого текста на диске |
| Интерфейс | бинарный кадровый протокол UDS (`~/.shopot/api.sock`) — единственный интерфейс; GUI-клиент рендерит, ядро делает всё остальное |

## Сборка

Нужен только [Zig 0.17.0](https://ziglang.org/download/).

```bash
make            # = cd zig && zig build -Doptimize=ReleaseFast
make test       # = cd zig && zig build test --summary all
```

Бинарник: `zig/zig-out/bin/shopot-zig`. Релизные сборки под
x86_64-linux-musl и aarch64-macos прикрепляются к каждому тегу `zig-v*`.

## Запуск

```bash
shopot-zig init          # личность: ~/.shopot/zig-seed (0600)
shopot-zig serve         # демон: ядро + UDS-апи (~/.shopot/api.sock)
```

Интерфейса командной строки нет: единственный клиент — GUI, подключающийся
к ядру по UDS бинарным кадровым протоколом (типизированные ответы, машинные
коды ошибок, события). Спецификация для авторов клиента:
[`zig/docs/ru/CORE-API.md`](../../zig/docs/ru/CORE-API.md) (API 1.0.0).

Добавление друга — одно действие: `CREATE_INVITE` выдаёт односторонний код
(`shopot://i/...`), держатель делает единственный `ACCEPT_INVITE`. Контакт,
сессия и доставка поднимаются ядром сами (LAN-поиск, автодозвон,
офлайн-outbox, подтверждения доставки ACK).

## Релей (скрытие IP)

```bash
# на любом сервере (VPS):
./shopot relay 0.0.0.0:9000

# у себя:
> invite bob relay vps.example.com:9000
# → код уходит bob-у; bob делает accept — и видит только адрес релея
```

## Криптография

- XX-подобное рукопожатие (X25519 + Ed25519, подписи транскрипта, сверка
  remote static)
- Двойное шифрование сообщений: рэтчет-цепочки поверх AEAD-потока
- Звонки: кадры 20 мс, ключ кадра = HKDF(секрет звонка, seq), свой AEAD
  транспорт
- Хранилище: append-only AEAD-лог, ни одного байта открытого текста

Детали: [`zig/docs/ru/PROTOCOL.md`](../../zig/docs/ru/PROTOCOL.md),
[SECURITY.md](SECURITY.md).

## Документация

| Документ | Содержание |
|---|---|
| [`zig/docs/ru/CORE-API.md`](../../zig/docs/ru/CORE-API.md) / [en](../../zig/docs/CORE-API.md) | бинарный UDS-интерфейс для GUI-клиентов (API 1.0.0) |
| [`zig/docs/ru/PROTOCOL.md`](../../zig/docs/ru/PROTOCOL.md) / [en](../../zig/docs/PROTOCOL.md) | байтовая спецификация провода v3 |
| [`zig/docs/ru/ARCHITECTURE.md`](../../zig/docs/ru/ARCHITECTURE.md) / [en](../../zig/docs/ARCHITECTURE.md) | слои, потоки данных, трединг |
| [`zig/docs/ru/ROADMAP.md`](../../zig/docs/ru/ROADMAP.md) / [en](../../zig/docs/ROADMAP.md) | технический план и анти-план |
| [SECURITY.md](SECURITY.md) / [en](../../SECURITY.md) | модель угроз, репортинг, инвентаризация крипты |
| [CONTRIBUTING.md](CONTRIBUTING.md) / [en](../../CONTRIBUTING.md) | правила контрибуции (kernel-style) |

## Официальный клиент

- Второй разработчик проекта shopot: [EryyynIT](https://github.com/EryyynIT)
- Официальный клиент shopot: [shopot](https://github.com/EryyynIT/shopot)

## Лицензия

MIT — см. [LICENSE](../../LICENSE).
