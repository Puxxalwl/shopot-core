// shopot-core — WebRTC DataChannel transport (libdatachannel).
//
// Manual signaling: each side's connection parameters (SDP + ICE candidates,
// gathered non-trickled) are serialized to a single base64url "code" the app
// shows to the user. Codes move between peers through any channel the users
// already trust — messenger, QR, voice call. shopot runs no rendezvous server.
#pragma once

#include "transport/channel.hpp"

#include <memory>
#include <string>

namespace rtc {
class PeerConnection;
class DataChannel;
} // namespace rtc

namespace shopot {

class RtcChannel : public IChannel {
public:
  RtcChannel() = default;
  ~RtcChannel() override;

  void set_callbacks(Cbs cbs) override;
  void send(const std::uint8_t* data, std::size_t len) override;
  std::size_t buffered_amount() const override;
  void close() override;

  /// base64url code describing our side, valid after ICE gathering completes.
  const std::string& local_code() const { return code_; }

private:
  friend std::unique_ptr<RtcChannel> rtc_make_offer(const std::string& stun_server);
  friend std::unique_ptr<RtcChannel> rtc_make_answer(const std::string& offer_code,
                                                     const std::string& stun_server);
  friend void rtc_apply_answer(RtcChannel& ch, const std::string& answer_code);

  void init(const std::string& stun_server);
  void wire_dc();
  std::string collect_code();  // blocks until ICE gathering completes (bounded)

  std::shared_ptr<rtc::PeerConnection> pc_;
  std::shared_ptr<rtc::DataChannel> dc_;
  Cbs cbs_;
  std::string code_;
  bool open_notified_ = false;
};

/// Enable libdatachannel debug logging to stderr (SHOPOT_LOG=1 does this too).
void rtc_enable_logging();

/// Create an offer: returns the channel, code available via local_code().
std::unique_ptr<RtcChannel> rtc_make_offer(const std::string& stun_server);
/// Consume an offer code, produce our answer code.
std::unique_ptr<RtcChannel> rtc_make_answer(const std::string& offer_code,
                                            const std::string& stun_server);
/// Offer side: consume the answer code. The channel opens when ICE connects.
void rtc_apply_answer(RtcChannel& ch, const std::string& answer_code);

} // namespace shopot
