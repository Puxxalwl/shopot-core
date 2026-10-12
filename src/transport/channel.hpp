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

// Wire framing: first byte selects the handler.
inline constexpr std::uint8_t kFrameControl = 0x10;   // plaintext JSON (hello handshake)
inline constexpr std::uint8_t kFrameEnvelope = 0x11;  // nonce(24) || sealed JSON envelope
inline constexpr std::uint8_t kFrameChunk = 0x12;     // file_id(16) || idx(4BE) || nonce(24) || sealed chunk

inline constexpr std::size_t kChunkSize = 16 * 1024;
inline constexpr std::size_t kBufferedHigh = 1024 * 1024;  // pause pumping above this
inline constexpr std::size_t kBufferedLow = 256 * 1024;    // resume below this

} // namespace shopot
