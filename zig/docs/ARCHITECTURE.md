# Архитектура (zig core)

## Принципы
1. std-only: ни одной внешней библиотеки. Криптография — композиция примитивов std.crypto.
2. ООП-границы через vtable-интерфейсы (core/interfaces.zig): Conn, Transport, Clock.
   Слои знают только интерфейсы — конкретика инжектируется (dependency inversion).
3. Ноль аллокаций на горячем пути: кадры и конверты кодируются в буферы вызывающего;
   аллокатор нужен только структуре с временем жизни (индекс лога, карта сессий).
4. Один смысл — один файл. Модуль импортирует только core/interfaces.zig, не соседей.

## Слои (сверху вниз)
- app/    REPL (listen/connect/msg/react/block/call)                [lead]
- core/   engine (контакты, блокировки, dispatch), session          [lead]
- proto/  бинарные конверты, кодек без аллокаций                    [proto-agent]
- crypto/ identity, handshake, ratchet, call_keys, aead, pad        [crypto-agent]
- net/    транспорт TCP/UDS, обфускация потока, heartbeat           [net-agent]
- store/  шифрованный append-only лог                               [store-agent]

## Поток данных сообщения
sendText -> envelope.encode (буфер на стеке) -> Conn.writeAll
(обфускация: pad до класса размера + ChaCha20Poly1305 кадра) -> TCP/UDS.
Приём: Conn.readAll -> decode -> Engine.dispatch -> блокировки -> callbacks.

## Потоки
- Один поток чтения на сессию; отправка под мьютексом сессии.
- Presence — без потока: чистая машина состояний, время инжектируется (Clock).

## Тесты
- Модульные в каждом файле (владельцы модулей), zig build test — общая проверка (лид).
