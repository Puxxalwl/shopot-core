// shopot-cli — helpers shared by the plain REPL and the TUI frontend.
#pragma once

#include "shopot/shopot.hpp"

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <thread>
#include <unistd.h>

namespace cli_support {

inline std::string read_keyfile(const std::string& path) {
  std::ifstream in(path);
  std::string words;
  std::getline(in, words);
  while (!words.empty() && (words.back() == '\n' || words.back() == '\r')) words.pop_back();
  return words;
}

inline void write_keyfile(const std::string& path, const std::string& words) {
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) throw std::runtime_error(std::string("cannot write key file: ") + strerror(errno));
  const std::string data = words + "\n";
  if (write(fd, data.data(), data.size()) != (ssize_t)data.size())
    throw std::runtime_error("cannot write key file");
  close(fd);
}

// Background keeper: keep searching for offline peers while the app runs, so
// exit/re-enter with the same DB is enough for queued messages to flush.
inline std::thread run_keeper(shopot::Engine& engine, const std::atomic<bool>& run) {
  return std::thread([&engine, &run] {
    while (run.load()) {
      try {
        engine.listen_invites();  // no-op when there are no pending invites
        for (const auto& c : engine.contacts())
          if (!c.online) engine.connect_auto(c.id);
      } catch (...) {
      }
      for (int i = 0; i < 100 && run.load(); ++i)  // 10 s, interruptible
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  });
}

inline std::string hhmm(std::int64_t ts_ms) {
  const std::time_t sec = static_cast<std::time_t>(ts_ms / 1000);
  std::tm tm{};
  localtime_r(&sec, &tm);
  char buf[8];
  std::snprintf(buf, sizeof buf, "%02d:%02d", tm.tm_hour, tm.tm_min);
  return buf;
}

inline std::string day_label(std::int64_t ts_ms) {
  const std::time_t sec = static_cast<std::time_t>(ts_ms / 1000);
  std::tm tm{};
  localtime_r(&sec, &tm);
  char buf[32];
  std::strftime(buf, sizeof buf, "%d.%m", &tm);
  return buf;
}

inline std::string human_size(std::uint64_t n) {
  char buf[32];
  if (n >= 1u << 30) { std::snprintf(buf, sizeof buf, "%.1f GB", double(n) / (1u << 30)); }
  else if (n >= 1u << 20) { std::snprintf(buf, sizeof buf, "%.1f MB", double(n) / (1u << 20)); }
  else if (n >= 1u << 10) { std::snprintf(buf, sizeof buf, "%.1f KB", double(n) / (1u << 10)); }
  else { std::snprintf(buf, sizeof buf, "%llu B", (unsigned long long)n); }
  return buf;
}

inline std::string mime_from_ext(const std::string& path) {
  const auto dot = path.rfind('.');
  std::string ext = dot == std::string::npos ? "" : path.substr(dot + 1);
  for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
  if (ext == "png") return "image/png";
  if (ext == "gif") return "image/gif";
  if (ext == "webp") return "image/webp";
  if (ext == "mp4" || ext == "mov" || ext == "webm") return "video/mp4";
  if (ext == "mp3") return "audio/mpeg";
  if (ext == "ogg" || ext == "opus") return "audio/ogg";
  if (ext == "pdf") return "application/pdf";
  if (ext == "txt" || ext == "md") return "text/plain";
  if (ext == "zip") return "application/zip";
  return "application/octet-stream";
}

inline bool is_image_mime(const std::string& mime) { return mime.rfind("image/", 0) == 0; }

} // namespace cli_support
