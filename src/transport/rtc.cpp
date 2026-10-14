#include "transport/rtc.hpp"

#include "crypto.hpp"

#include <rtc/rtc.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdexcept>

namespace shopot {

namespace {

struct CodeParts {
  std::string type;
  std::string sdp;
  std::vector<std::pair<std::string, std::string>> candidates;  // (candidate, mid)
};

CodeParts code_parse(const std::string& code) {
  crypto::Bytes raw;
  try {
    raw = crypto::b64d(code);
  } catch (...) {
    throw std::invalid_argument("bad connection code (not base64)");
  }
  const auto j = nlohmann::json::parse(raw.begin(), raw.end());
  CodeParts p;
  p.type = j.at("type").get<std::string>();
  p.sdp = j.at("sdp").get<std::string>();
  for (const auto& c : j.at("candidates"))
    p.candidates.emplace_back(c.at("c").get<std::string>(), c.at("m").get<std::string>());
  return p;
}

} // namespace

void rtc_enable_logging() {
  static bool done = false;
  if (done) return;
  done = true;
  rtc::InitLogger(rtc::LogLevel::Debug,
                  [](rtc::LogLevel, std::string msg) { std::fprintf(stderr, "[rtc] %s\n", msg.c_str()); });
}

void RtcChannel::init(const std::string& stun_server) {
  if (std::getenv("SHOPOT_LOG")) rtc_enable_logging();
  rtc::Configuration cfg;
  if (!stun_server.empty()) cfg.iceServers.emplace_back(stun_server);
  // No TURN: relays would be someone else's server mediating the connection.
  // Symmetric-NAT pairs may fail to connect; that is the honest price of
  // zero-infrastructure operation.
  // We drive offer/answer explicitly; auto-negotiation would race us by
  // generating the answer inside setRemoteDescription() before we gather.
  cfg.disableAutoNegotiation = true;
  pc_ = std::make_shared<rtc::PeerConnection>(cfg);
  pc_->onIceStateChange([](rtc::PeerConnection::IceState s) {
    std::fprintf(stderr, "[rtc] ICE state -> %d\n", static_cast<int>(s));
  });
}

void RtcChannel::wire_dc() {
  dc_->setBufferedAmountLowThreshold(kBufferedLow);
  dc_->onOpen([this] {
    if (!open_notified_) {
      open_notified_ = true;
      if (cbs_.on_open) cbs_.on_open();
    }
  });
  dc_->onMessage([this](rtc::message_variant msg) {
    if (!cbs_.on_message) return;
    if (std::holds_alternative<rtc::binary>(msg)) {
      const rtc::binary& b = std::get<rtc::binary>(msg);
      if (!b.empty())
        cbs_.on_message(reinterpret_cast<const std::uint8_t*>(b.data()), b.size());
    } else {
      const std::string& s = std::get<std::string>(msg);
      cbs_.on_message(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    }
  });
  const auto closed = [this] {
    if (cbs_.on_closed) cbs_.on_closed();
  };
  dc_->onClosed(closed);
  dc_->onError([closed](std::string) { closed(); });
  dc_->onBufferedAmountLow([this] {
    if (cbs_.on_writable) cbs_.on_writable();
  });
}

void RtcChannel::send_audio(const std::uint8_t* data, std::size_t len) {
  if (!adc_ || !adc_->isOpen()) return;  // no call lane / call not up: drop
  try {
    adc_->send(reinterpret_cast<const std::byte*>(data), len);
  } catch (...) {
  }
}

void RtcChannel::wire_adc(const std::shared_ptr<rtc::DataChannel>& dc) {
  dc->onMessage([this](rtc::message_variant msg) {
    if (!cbs_.on_audio) return;
    if (std::holds_alternative<rtc::binary>(msg)) {
      const rtc::binary& b = std::get<rtc::binary>(msg);
      if (!b.empty())
        cbs_.on_audio(reinterpret_cast<const std::uint8_t*>(b.data()), b.size());
    }
  });
}

// labels both lanes; called for channels arriving from the remote side
bool RtcChannel::accept_remote_dc(const std::shared_ptr<rtc::DataChannel>& dc) {
  const std::string label = dc->label();
  if (label == "shopot") {
    dc_ = dc;
    wire_dc();
    return true;
  }
  if (label == "shopot-call") {
    adc_ = dc;
    wire_adc(dc);
    return true;
  }
  return false;
}

std::string RtcChannel::collect_code() {
  std::mutex mu;
  std::condition_variable cv;
  bool gathered = false;
  std::vector<std::pair<std::string, std::string>> cands;

  pc_->onLocalCandidate([&](const rtc::Candidate& c) {
    std::lock_guard lk(mu);
    if (!c.isResolved()) return;
    cands.emplace_back(std::string(c), c.mid());
  });
  pc_->onGatheringStateChange([&](rtc::PeerConnection::GatheringState state) {
    if (state == rtc::PeerConnection::GatheringState::Complete) {
      std::lock_guard lk(mu);
      gathered = true;
      cv.notify_one();
    }
  });

  pc_->setLocalDescription();  // starts ICE gathering

  {
    std::unique_lock lk(mu);
    // Bound the wait: on odd networks gathering can stall; host candidates
    // alone may still be enough (LAN, static IP, VPN mesh).
    cv.wait_for(lk, std::chrono::seconds(8), [&] { return gathered; });
  }

  std::lock_guard lk(mu);
  const auto desc = pc_->localDescription();
  if (!desc) throw std::runtime_error("no local description");
  nlohmann::json j;
  j["type"] = desc->typeString();
  j["sdp"] = std::string(*desc);
  j["candidates"] = nlohmann::json::array();
  for (const auto& [c, m] : cands) j["candidates"].push_back({{"c", c}, {"m", m}});
  const std::string s = j.dump();
  code_ = crypto::b64e(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  return code_;
}

void RtcChannel::set_callbacks(Cbs cbs) {
  cbs_ = std::move(cbs);
  if (open_notified_ && cbs_.on_open) cbs_.on_open();  // opened before callbacks set
}

void RtcChannel::send(const std::uint8_t* data, std::size_t len) {
  if (!dc_ || !dc_->isOpen()) return;  // dropped; payload lives in the outbox
  try {
    dc_->send(reinterpret_cast<const std::byte*>(data), len);
  } catch (...) {
  }
}

std::size_t RtcChannel::buffered_amount() const {
  if (!dc_) return 0;
  try {
    return dc_->bufferedAmount();
  } catch (...) {
    return 0;
  }
}

void RtcChannel::close() {
  try {
    if (dc_) dc_->close();
  } catch (...) {
  }
}

RtcChannel::~RtcChannel() {
  try {
    close();
    if (pc_) pc_->close();
  } catch (...) {
  }
}

// ------------------------------------------------------------------ signaling

std::unique_ptr<RtcChannel> rtc_make_offer(const std::string& stun_server) {
  auto ch = std::make_unique<RtcChannel>();
  ch->init(stun_server);
  ch->dc_ = ch->pc_->createDataChannel("shopot");
  ch->wire_dc();
  // call lane: unordered, zero retransmits — stale audio is worse than lost
  rtc::DataChannelInit init;
  init.reliability.unordered = true;
  init.reliability.maxRetransmits = 0;
  ch->adc_ = ch->pc_->createDataChannel("shopot-call", init);
  ch->wire_adc(ch->adc_);
  ch->collect_code();
  return ch;
}

std::unique_ptr<RtcChannel> rtc_make_answer(const std::string& offer_code,
                                            const std::string& stun_server) {
  const CodeParts offer = code_parse(offer_code);
  auto ch = std::make_unique<RtcChannel>();
  ch->init(stun_server);
  ch->pc_->onDataChannel([ch = ch.get()](std::shared_ptr<rtc::DataChannel> dc) {
    ch->accept_remote_dc(dc);
  });
  ch->pc_->setRemoteDescription(rtc::Description(offer.sdp, offer.type));
  for (const auto& [c, m] : offer.candidates) ch->pc_->addRemoteCandidate(rtc::Candidate(c, m));
  ch->collect_code();  // gathers our answer
  return ch;
}

void rtc_apply_answer(RtcChannel& ch, const std::string& answer_code) {
  const CodeParts answer = code_parse(answer_code);
  ch.pc_->setRemoteDescription(rtc::Description(answer.sdp, answer.type));
  for (const auto& [c, m] : answer.candidates) ch.pc_->addRemoteCandidate(rtc::Candidate(c, m));
}

} // namespace shopot
