# Архитектура (zig core)

## Принципы
1. std-only: ни одной внешней библиотеки. Криптография — композиция примитивов std.crypto.
2. ООП-границы через vtable-интерфейсы (core/interfaces.zig): Conn, Transport, Clock.
   Слои знают только интерфейсы — конкретика инжектируется (dependency inversion).
3. Ноль аллокаций на горячем пути: кадры и конверты кодируются в буферы вызывающего;
   аллокатор нужен только структуре с временем жизни (индекс лога, карта сессий).
4. Один смысл — один файл. Модуль импортирует только core/interfaces.zig, не соседей.

## Слои (сверху вниз)
- app/    REPL/TUI/CLI-сервер (listen/connect/msg/react/block/call)
- core/   engine (контакты, блокировки, dispatch), session
- proto/  бинарные конверты, кодек без аллокаций
- crypto/ identity, handshake, ratchet, call_keys, aead, pad
- net/    транспорт TCP, обфускация потока, heartbeat
- store/  шифрованный append-only лог

## Поток данных сообщения
sendText -> envelope.encode (буфер на стеке) -> Conn.writeAll
(обфускация: pad до класса размера + ChaCha20Poly1305 кадра) -> TCP.
Приём: Conn.readAll -> decode -> Engine.dispatch -> блокировки -> callbacks.

## Потоки
- Один поток чтения на сессию; отправка под мьютексом сессии.
- Presence — без потока: чистая машина состояний, время инжектируется (Clock).

## Тесты
- Модульные в каждом файле (владельцы модулей), zig build test — общая проверка (лид).
