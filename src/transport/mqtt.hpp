#pragma once

// MQTT 3.1.1 over WebSocket — the minimum needed to use public brokers
// (EMQX, Mosquitto) as dumb rendezvous mailboxes: CONNECT/CONNACK, QoS-0
// SUBSCRIBE/PUBLISH with retain, PINGREQ keepalive. No new dependencies:
// rides on libdatachannel's rtc::WebSocket (wss, subprotocol "mqtt"), so the
// transport is TLS-encrypted and the broker still only ever sees an opaque
// topic hash plus a sealed blob.

#ifdef SHOPOT_WITH_RTC

#include "isignaling.hpp"

#include "mqtt_packets.hpp"
#include <rtc/websocket.hpp>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace shopot::signal {

// ---- client -----------------------------------------------------------------

class MqttClient {
public:
  explicit MqttClient(const std::string& url);  // wss://host:port/path
  ~MqttClient();
  MqttClient(const MqttClient&) = delete;
  MqttClient& operator=(const MqttClient&) = delete;

  // resolves when the broker accepted us (CONNACK rc=0); false on timeout
  bool connect_wait(std::int64_t timeout_ms);
  void subscribe(const std::string& topic);
  void publish(const std::string& topic, const std::string& payload, bool retain);
  // services the socket for ms: delivers inbound PUBLISH, sends PINGREQ
  void pump(std::int64_t ms);
  bool alive() const;

  std::vector<MqttPacket> drain();

private:
  void feed(const std::uint8_t* d, std::size_t n);
  void send_raw(const std::vector<std::uint8_t>& bytes);

  std::shared_ptr<rtc::WebSocket> ws_;
  const std::string client_id_;
  const std::uint16_t keepalive_s_ = 60;

  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::vector<std::uint8_t> inbuf_;
  std::deque<MqttPacket> inbox_;
  bool connack_ok_ = false;
  std::chrono::steady_clock::time_point last_ctrl_{std::chrono::steady_clock::now()};
};

// ---- high-level rendezvous over public brokers -------------------------------

class MqttSignaling final : public ISignaling {
public:
  // tries urls in order, then keeps cycling on connection loss
  explicit MqttSignaling(std::vector<std::string> urls);
  ~MqttSignaling() override;
  MqttSignaling(const MqttSignaling&) = delete;
  MqttSignaling& operator=(const MqttSignaling&) = delete;

  bool ok() const override;
  void subscribe(const std::string& topic) override;
  void publish(const std::string& topic, const std::string& payload) override;
  bool flush_pending(std::int64_t timeout_ms) override;
  std::vector<Msg> poll(std::int64_t wait_ms) override;

private:
  void run();

  const std::vector<std::string> urls_;
  std::thread worker_;
  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::deque<std::string> want_topics_;
  std::deque<Msg> outbox_;
  std::deque<Msg> inbox_;
  std::unique_ptr<MqttClient> client_;
  std::atomic<bool> stopping_{false};
  std::atomic<bool> ok_{false};
};

} // namespace shopot::signal

#endif // SHOPOT_WITH_RTC
