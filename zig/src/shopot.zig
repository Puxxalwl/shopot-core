//! shopot-zig: serverless encrypted messenger core. std-only.
pub const interfaces = @import("shopot/core/interfaces.zig");

pub const crypto = struct {
    pub const kdf = @import("shopot/crypto/kdf.zig");
    pub const aead = @import("shopot/crypto/aead.zig");
    pub const identity = @import("shopot/crypto/identity.zig");
    pub const handshake = @import("shopot/crypto/handshake.zig");
    pub const ratchet = @import("shopot/crypto/ratchet.zig");
    pub const call_keys = @import("shopot/crypto/call_keys.zig");
    pub const pad = @import("shopot/crypto/pad.zig");
};

pub const proto = struct {
    pub const codec = @import("shopot/proto/codec.zig");
    pub const envelope = @import("shopot/proto/envelope.zig");
};

pub const net = struct {
    pub const framing = @import("shopot/net/framing.zig");
    pub const obfuscate = @import("shopot/net/obfuscate.zig");
    pub const heartbeat = @import("shopot/net/heartbeat.zig");
    pub const tcp = @import("shopot/net/tcp.zig");
};

pub const store = struct {
    pub const log = @import("shopot/store/log.zig");
};

test {
    std.testing.refAllDecls(@This());
}
const std = @import("std");

pub const core = struct {
    pub const interfaces = @import("shopot/core/interfaces.zig");
    pub const session = @import("shopot/core/session.zig");
    pub const engine = @import("shopot/core/engine.zig");
};
