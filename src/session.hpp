// shopot-core — per-contact protocol session.
//
// Lifecycle: channel opens -> both sides send a signed hello -> each verifies
// the signature against the contact's identity key and derives a session key
// (forward secrecy) -> outbox for this contact is flushed, pending file
// transfers start -> envelopes flow until the channel dies.
//
// Sending while offline: payloads wait in the encrypted outbox table and are
// flushed by whichever session establishes first. Delivery is confirmed by
// ack envelopes; unacked payloads are re-sent on the next session (the
// receiver deduplicates by message id).
#pragma once

#include "crypto.hpp"
#include "db.hpp"
#include "transport/channel.hpp"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>

namespace shopot {

struct SessionEvents {
  // All events are emitted from the session's own threads; the Engine
  // re-dispatches them onto one dispatcher thread before calling user code.
  std::function<void(std::int64_t contact, bool online)> presence;
  std::function<void(const MessageRow&)> message;
  std::function<void(const std::string& msg_id, MsgStatus)> status;
  std::function<void(const FileRow&)> file_progress;
  std::function<void(const FileRow&)> file_ready;  // incoming file assembled & verified
  std::function<void(std::int64_t contact, std::string what)> error;
};

class Session : public std::enable_shared_from_this<Session> {
public:
  Session(const crypto::Identity& id, const ContactRow& contact, Db& db,
          std::unique_ptr<IChannel> channel, SessionEvents ev, std::string download_dir);
  ~Session();

  void start();
  void stop();  // idempotent
  IChannel* channel() { return ch_.get(); }
  bool established() const { return established_.load(); }

  /// Seal and send one outbox payload right now (must be established).
  void send_payload(const std::string& msg_id, const crypto::Bytes& envelope_plain);
  /// Start pumping one pending outgoing file right now (must be established).
  void send_file_now(const FileRow& f) { tx_push(TxItem{.kind = TxItem::PumpFile, .file = f}); }
  /// Ask the tx thread to re-scan the outbox and pending files.
  void kick();

  // v2 frame helpers (ratchet-sealed): [dh(32)][pn(4)][n(4)][nonce(24)][ct]
  crypto::Bytes ratchet_seal(const std::uint8_t* data, std::size_t len);
  crypto::Bytes ratchet_open(const std::uint8_t* data, std::size_t len);

private:
  struct TxItem {
    enum Kind { Frame, Flush, PumpFile, Stop } kind = Frame;
    crypto::Bytes frame{};
    FileRow file{};
  };

  void wire_callbacks();
  void on_channel_message(const std::uint8_t* data, std::size_t len);
  void handle_control(const std::uint8_t* data, std::size_t len);
  void handle_envelope(const std::uint8_t* data, std::size_t len);
  void handle_chunk(const std::uint8_t* data, std::size_t len);

  void maybe_establish();
  void send_hello();
  void ack(const std::string& ref);

  void tx_loop();
  void tx_push(TxItem item);
  void do_flush();
  void do_pump(const FileRow& file);
  void wait_writable();

  void complete_file(FileRow& f);

  const crypto::Identity& id_;
  ContactRow contact_;
  Db& db_;
  std::unique_ptr<IChannel> ch_;
  SessionEvents ev_;
  std::string download_dir_;
  crypto::Arr<32> room_{};

  std::mutex mu_;  // guards crypto state below
  crypto::Arr<32> eph_sk_{};
  bool have_eph_ = false;
  bool have_peer_eph_ = false;
  crypto::Arr<32> peer_eph_{};
  crypto::DoubleRatchet ratchet_{};  // v2: per-message keys, DH re-key every 256 sends

  std::atomic<bool> established_{false};
  std::atomic<bool> closed_{false};

  std::mutex tx_mu_;
  std::condition_variable tx_cv_;
  std::queue<TxItem> tx_q_;
  std::thread tx_thread_;

  std::mutex wr_mu_;
  std::condition_variable wr_cv_;
};

} // namespace shopot
