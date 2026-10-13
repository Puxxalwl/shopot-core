#include "mqtt.hpp"

#ifdef SHOPOT_WITH_RTC

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace shopot::signal {

namespace {
constexpr std::size_t kMaxPacket = 1024 * 1024;  // brokers allow ~1MB; we need ~4KB

// optional trace: SHOPOT_SIGNAL_DEBUG=1
bool sig_debug() {
  static const bool on = std::getenv("SHOPOT_SIGNAL_DEBUG") != nullptr;
  return on;
}
void trace(const std::string& line) {
  if (sig_debug()) std::fprintf(stderr, "[signal] %s\n", line.c_str());
}

void put_varint(std::vector<std::uint8_t>& v, std::size_t n) {
  do {
    const std::uint8_t b = static_cast<std::uint8_t>(n % 128);
    n /= 128;
    v.push_back(n ? static_cast<std::uint8_t>(b | 0x80) : b);
  } while (n);
}

void put_str(std::vector<std::uint8_t>& v, const std::string& s) {
  v.push_back(static_cast<std::uint8_t>((s.size() >> 8) & 0xFF));
  v.push_back(static_cast<std::uint8_t>(s.size() & 0xFF));
  v.insert(v.end(), s.begin(), s.end());
}

std::vector<std::uint8_t> frame(std::uint8_t type_flags, const std::vector<std::uint8_t>& body) {
  std::vector<std::uint8_t> out{type_flags};
  put_varint(out, body.size());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}
} // namespace

// ------------------------------------------------------------------ packets

std::vector<std::uint8_t> mqtt_connect(const std::string& client_id, std::uint16_t keepalive_s) {
  std::vector<std::uint8_t> body{0x00, 0x04, 'M', 'Q', 'T', 'T',
                                 0x04,  // protocol level 4 (MQTT 3.1.1)
                                 0x02};  // clean session
  body.push_back(static_cast<std::uint8_t>(keepalive_s >> 8));
  body.push_back(static_cast<std::uint8_t>(keepalive_s & 0xFF));
  put_str(body, client_id);
  return frame(0x10, body);
}

std::vector<std::uint8_t> mqtt_subscribe(const std::string& topic, std::uint16_t packet_id) {
  std::vector<std::uint8_t> body;
  body.push_back(static_cast<std::uint8_t>(packet_id >> 8));
  body.push_back(static_cast<std::uint8_t>(packet_id & 0xFF));
  put_str(body, topic);
  body.push_back(0x00);  // QoS 0
  return frame(0x82, body);
}

std::vector<std::uint8_t> mqtt_publish(const std::string& topic, const std::string& payload,
                                       bool retain) {
  std::vector<std::uint8_t> body;
  put_str(body, topic);
  body.insert(body.end(), payload.begin(), payload.end());
  return frame(static_cast<std::uint8_t>(0x30 | (retain ? 1 : 0)), body);
}

std::vector<std::uint8_t> mqtt_pingreq() { return frame(0xC0, {}); }
std::vector<std::uint8_t> mqtt_disconnect() { return frame(0xE0, {}); }

std::size_t mqtt_parse_one(const std::uint8_t* data, std::size_t len, MqttPacket& out) {
  if (len < 2) return 0;
  std::size_t rem = 0, mult = 1, pos = 1;
  for (;;) {
    if (pos >= len) return 0;  // incomplete remaining-length varint
    const std::uint8_t b = data[pos++];
    rem += static_cast<std::size_t>(b & 0x7F) * mult;
    if ((b & 0x80) == 0) break;
    mult *= 128;
    if (mult > 128ULL * 128 * 128 * 128) return 0;
  }
  if (rem > kMaxPacket) return 0;  // refuse absurd packets (stall = reconnect)
  if (len - pos < rem) return 0;   // wait for the full body
  out.type_flags = data[0];
  const std::uint8_t* body = data + pos;
  out.topic.clear();
  out.payload.clear();
  if ((out.type_flags >> 4) == 3) {  // PUBLISH: topic, then (pid if qos>0), then message
    if (rem >= 2) {
      const std::size_t tl = (static_cast<std::size_t>(body[0]) << 8) | body[1];
      if (2 + tl <= rem) {
        out.topic.assign(reinterpret_cast<const char*>(body) + 2, tl);
        const std::size_t qos = (out.type_flags >> 1) & 3;
        const std::size_t skip = 2 + tl + (qos ? 2 : 0);
        if (skip <= rem)
          out.payload.assign(reinterpret_cast<const char*>(body) + skip, rem - skip);
      }
    }
  } else {
    out.payload.assign(reinterpret_cast<const char*>(body), rem);
  }
  return pos + rem;
}

// ------------------------------------------------------------------ client

MqttClient::MqttClient(const std::string& url)
    : client_id_("shopot-" + crypto::new_id().substr(0, 8)) {
  rtc::WebSocketConfiguration c;
  c.protocols = {"mqtt"};  // required by the MQTT-over-WebSocket spec
  c.connectionTimeout = std::chrono::milliseconds(10000);
  c.pingInterval = std::chrono::milliseconds(30000);
  ws_ = std::make_shared<rtc::WebSocket>(c);
  ws_->onOpen([this] {
    const auto bytes = mqtt_connect(client_id_, keepalive_s_);
    ws_->send(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  });
  ws_->onMessage([this](rtc::message_variant m) {
    if (auto* b = std::get_if<rtc::binary>(&m); b && !b->empty())
      feed(reinterpret_cast<const std::uint8_t*>(b->data()), b->size());
  });
  ws_->onClosed([this] {
    std::lock_guard lk(mu_);
    connack_ok_ = false;
    cv_.notify_all();
  });
  ws_->open(url);
}

MqttClient::~MqttClient() {
  try {
    if (ws_ && !ws_->isClosed()) {
      if (ws_->isOpen()) {
        const auto bye = mqtt_disconnect();
        ws_->send(reinterpret_cast<const std::byte*>(bye.data()), bye.size());
      }
      ws_->forceClose();
    }
  } catch (...) {
  }
}

void MqttClient::send_raw(const std::vector<std::uint8_t>& bytes) {
  try {
    ws_->send(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  } catch (...) {
  }
}

bool MqttClient::connect_wait(std::int64_t timeout_ms) {
  std::unique_lock lk(mu_);
  return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms), [this] { return connack_ok_; });
}

void MqttClient::subscribe(const std::string& topic) {
  std::lock_guard lk(mu_);
  if (connack_ok_) send_raw(mqtt_subscribe(topic, 1));
}

void MqttClient::publish(const std::string& topic, const std::string& payload, bool retain) {
  std::lock_guard lk(mu_);
  if (connack_ok_) send_raw(mqtt_publish(topic, payload, retain));
}

void MqttClient::pump(std::int64_t ms) {
  std::unique_lock lk(mu_);
  cv_.wait_for(lk, std::chrono::milliseconds(ms));
  const auto now = std::chrono::steady_clock::now();
  if (connack_ok_ && now - last_ctrl_ > std::chrono::seconds(keepalive_s_ / 2)) {
    send_raw(mqtt_pingreq());
    last_ctrl_ = now;
  }
}

bool MqttClient::alive() const {
  std::lock_guard lk(mu_);
  return connack_ok_;
}

std::vector<MqttPacket> MqttClient::drain() {
  std::lock_guard lk(mu_);
  std::vector<MqttPacket> out(std::make_move_iterator(inbox_.begin()),
                              std::make_move_iterator(inbox_.end()));
  inbox_.clear();
  return out;
}

void MqttClient::feed(const std::uint8_t* d, std::size_t n) {
  std::lock_guard lk(mu_);
  inbuf_.insert(inbuf_.end(), d, d + n);
  std::size_t consumed = 0;
  bool notify = false;
  while (consumed < inbuf_.size()) {
    MqttPacket p;
    const std::size_t used = mqtt_parse_one(inbuf_.data() + consumed, inbuf_.size() - consumed, p);
    if (used == 0) break;
    consumed += used;
    if (p.type_flags == 0) continue;
    last_ctrl_ = std::chrono::steady_clock::now();
    const std::uint8_t type = p.type_flags >> 4;
    if (type == 2) {  // CONNACK: flags || return-code
      connack_ok_ = p.payload.size() >= 2 && p.payload[1] == 0;
      notify = true;
    } else if (type == 3 && !p.topic.empty()) {
      inbox_.push_back(std::move(p));
      notify = true;
    }
    // SUBACK(9) / PINGRESP(13): the keepalive refresh is all they need
  }
  if (consumed) inbuf_.erase(inbuf_.begin(), inbuf_.begin() + static_cast<long>(consumed));
  if (notify) cv_.notify_all();
}

// ------------------------------------------------------------------ signaling

MqttSignaling::MqttSignaling(std::vector<std::string> urls) : urls_(std::move(urls)) {
  if (urls_.empty()) throw std::invalid_argument("no rendezvous relays configured");
  worker_ = std::thread([this] { run(); });
}

MqttSignaling::~MqttSignaling() {
  stopping_.store(true);
  if (worker_.joinable()) worker_.join();
}

bool MqttSignaling::ok() const { return ok_.load(); }

void MqttSignaling::subscribe(const std::string& topic) {
  {
    std::lock_guard lk(mu_);
    if (std::find(want_topics_.begin(), want_topics_.end(), topic) == want_topics_.end())
      want_topics_.push_back(topic);
  }
  cv_.notify_one();
}

void MqttSignaling::publish(const std::string& topic, const std::string& payload) {
  {
    std::lock_guard lk(mu_);
    outbox_.emplace_back(topic, payload);
  }
  cv_.notify_one();
}

bool MqttSignaling::flush_pending(std::int64_t timeout_ms) {
  std::unique_lock lk(mu_);
  return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms), [this] { return outbox_.empty(); });
}

std::vector<MqttSignaling::Msg> MqttSignaling::poll(std::int64_t wait_ms) {
  std::unique_lock lk(mu_);
  cv_.wait_for(lk, std::chrono::milliseconds(wait_ms));
  std::vector<Msg> out(std::make_move_iterator(inbox_.begin()),
                       std::make_move_iterator(inbox_.end()));
  inbox_.clear();
  return out;
}

void MqttSignaling::run() {
  std::size_t url_i = 0;
  while (!stopping_.load()) {
    trace("dialing " + urls_[url_i]);
    MqttClient cl(urls_[url_i]);
    if (cl.connect_wait(10000)) {
      trace("connected: " + urls_[url_i]);
      ok_.store(true);
      std::deque<std::string> wants;
      std::deque<Msg> out;
      {
        std::lock_guard lk(mu_);
        wants.swap(want_topics_);
        out.swap(outbox_);
      }
      for (const auto& t : wants) {
        cl.subscribe(t);
        trace("subscribed " + t);
      }
      for (const auto& [t, p] : out) {
        cl.publish(t, p, true);  // retained: late peer gets it
        trace("published " + std::to_string(p.size()) + "B -> " + t);
      }
      while (!stopping_.load() && cl.alive()) {
        // apply anything the engine queued meanwhile
        std::deque<std::string> new_wants;
        std::deque<Msg> new_out;
        {
          {
            std::lock_guard lk(mu_);
            new_wants.swap(want_topics_);
            new_out.swap(outbox_);
          }
          cv_.notify_all();  // flush_pending may be waiting on an empty queue
        }
        for (const auto& t : new_wants) cl.subscribe(t);
        for (const auto& [t, p] : new_out) cl.publish(t, p, true);
        if (!new_out.empty()) trace("published " + std::to_string(new_out.size()) + " queued");
        cl.pump(50);
        for (auto& p : cl.drain()) {
          trace("inbound " + std::to_string(p.payload.size()) + "B on " + p.topic);
          std::lock_guard lk(mu_);
          inbox_.emplace_back(std::move(p.topic), std::move(p.payload));
        }
        cv_.notify_all();
      }
    }
    trace("connection lost / failed; cycling relay");
    ok_.store(false);
    if (stopping_.load()) break;
    url_i = (url_i + 1) % urls_.size();
    for (int i = 0; i < 30 && !stopping_.load(); ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

} // namespace shopot::signal

#endif // SHOPOT_WITH_RTC
