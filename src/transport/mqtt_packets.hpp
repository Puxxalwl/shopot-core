#pragma once

// MQTT 3.1.1 minimal packet builders/parser — transport-free and dependency-
// free so tests and non-RTC builds can use them. The MQTT client lives in
// mqtt.hpp/mqtt.cpp (MQTT over rtc::WebSocket, SHOPOT_WITH_RTC builds only).

#include <cstdint>
#include <string>
#include <vector>

namespace shopot::signal {

std::vector<std::uint8_t> mqtt_connect(const std::string& client_id, std::uint16_t keepalive_s);
std::vector<std::uint8_t> mqtt_subscribe(const std::string& topic, std::uint16_t packet_id);
std::vector<std::uint8_t> mqtt_publish(const std::string& topic, const std::string& payload,
                                       bool retain);
std::vector<std::uint8_t> mqtt_pingreq();
std::vector<std::uint8_t> mqtt_disconnect();

struct MqttPacket {
  std::uint8_t type_flags = 0;  // full first byte; packet type = type_flags >> 4
  std::string topic;            // PUBLISH only
  std::string payload;          // PUBLISH: message; other packets: raw body
};

// Parses one packet from data[0..len). Returns bytes consumed, or 0 when more
// bytes are needed. For non-PUBLISH packets the raw body lands in payload.
std::size_t mqtt_parse_one(const std::uint8_t* data, std::size_t len, MqttPacket& out);

} // namespace shopot::signal
