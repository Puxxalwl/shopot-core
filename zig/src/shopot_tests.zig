//! Тестовый корень модуля: zig build test гоняет через этот файл тесты
//! ВСЕХ подмодулей (тесты файлов, импортированных только внутри вложенных
//! контейнеров shopot.zig, компилятором не собираются — здесь импорт явный).
test {
    _ = @import("shopot/core/interfaces.zig");
    _ = @import("shopot/core/session.zig");
    _ = @import("shopot/core/engine.zig");
    _ = @import("shopot/crypto/kdf.zig");
    _ = @import("shopot/crypto/aead.zig");
    _ = @import("shopot/crypto/identity.zig");
    _ = @import("shopot/crypto/handshake.zig");
    _ = @import("shopot/crypto/ratchet.zig");
    _ = @import("shopot/crypto/call_keys.zig");
    _ = @import("shopot/crypto/pad.zig");
    _ = @import("shopot/proto/codec.zig");
    _ = @import("shopot/proto/envelope.zig");
    _ = @import("shopot/net/framing.zig");
    _ = @import("shopot/net/obfuscate.zig");
    _ = @import("shopot/net/faketls.zig");
    _ = @import("shopot/net/relay.zig");
    _ = @import("shopot/net/heartbeat.zig");
    _ = @import("shopot/net/tcp.zig");
    _ = @import("shopot/app/adpcm.zig");
    _ = @import("shopot/app/api.zig");
    _ = @import("shopot/app/search.zig");
    _ = @import("shopot/store/log.zig");
}
