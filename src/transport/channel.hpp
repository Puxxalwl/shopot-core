// shopot-core — transport abstraction.
//
// The engine talks to a peer through an IChannel: an ordered, reliable,
// message-oriented bidirectional pipe. The reference implementation is
// WebRTC DataChannels (transport/rtc.cpp); tests use an in-memory loopback.
// Anything providing these semantics (Tor onion service, I2P, Bluetooth RFCOMM
// via a shim) can be plugged in without touching the protocol code.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace shopot {

struct IChannel {
  struct Cbs {
    std::function<void()> on_open;                          // ready to send
    std::function<void(const std::uint8_t*, std::size_t)> on_message;
    std::function<void()> on_closed;                        // terminal
    std::function<void()> on_writable;                      // buffered amount dropped low
  };
  virtual ~IChannel() = default;
  virtual void set_callbacks(Cbs cbs) = 0;
  /// Thread-safe. May be called before on_open; implementation may queue or drop.
  virtual void send(const std::uint8_t* data, std::size_t len) = 0;
  virtual std::size_t buffered_amount() const = 0;
  virtual void close() = 0;
};

// Wire framing (v2): first byte selects the handler. 0x11/0x12 bodies carry a
// 40-byte double-ratchet header — dh(32) || pn(4BE) || n(4BE) — before the
// sealed payload; a fresh message key protects every single frame.
inline constexpr std::uint8_t kFrameControl = 0x10;   // plaintext JSON (hello handshake)
inline constexpr std::uint8_t kFrameEnvelope = 0x11;  // ratchet hdr || nonce(24) || sealed JSON
inline constexpr std::uint8_t kFrameChunk = 0x12;     // ratchet hdr || sealed(file_id(16) || idx(4BE) || data)

inline constexpr std::size_t kChunkSize = 64 * 1024;        // v2: 4x fewer frames per byte
inline constexpr std::size_t kBufferedHigh = 2 * 1024 * 1024;  // pause pumping above this
inline constexpr std::size_t kBufferedLow = 512 * 1024;        // resume below this

} // namespace shopot
