#pragma once

#include "crypto.hpp"
#include "db.hpp"
#include "session.hpp"
#include "shopot/shopot.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>

namespace shopot {

struct Engine::Impl {
  Config cfg;
  Events ev;
  crypto::Identity id;
  Db db;

  mutable std::mutex mu_;  // guards sessions_
  std::unordered_map<std::int64_t, std::shared_ptr<Session>> sessions_;

  // event dispatcher: user callbacks run serialized on this one thread
  std::mutex eq_mu_;
  std::condition_variable eq_cv_;
  std::queue<std::function<void()>> eq_;
  std::thread eq_thread_;
  std::atomic<bool> stopping_{false};

  Impl(Config c, const std::string& mnemonic, Events events)
      : cfg(std::move(c)),
        ev(std::move(events)),
        id(crypto::Identity::from_entropy(crypto::mnemonic_to_entropy(mnemonic))),
        db(cfg.db_path, id.storage) {
    eq_thread_ = std::thread([this] { dispatcher_loop(); });
  }

  ~Impl() {
    {
      std::lock_guard lk(mu_);
      for (auto& [cid, s] : sessions_) s->stop();
      sessions_.clear();
    }
    stopping_.store(true);
    eq_cv_.notify_one();
    if (eq_thread_.joinable()) eq_thread_.join();
  }

  void dispatch(std::function<void()> fn) {
    {
      std::lock_guard lk(eq_mu_);
      eq_.push(std::move(fn));
    }
    eq_cv_.notify_one();
  }

  void dispatcher_loop() {
    for (;;) {
      std::function<void()> fn;
      {
        std::unique_lock lk(eq_mu_);
        eq_cv_.wait(lk, [&] { return stopping_ || !eq_.empty(); });
        if (eq_.empty()) return;
        fn = std::move(eq_.front());
        eq_.pop();
      }
      try {
        fn();
      } catch (...) {
      }
    }
  }

  SessionEvents session_events() {
    SessionEvents sev;
    sev.presence = [this](std::int64_t cid, bool on) {
      if (ev.on_presence) dispatch([this, cid, on] { ev.on_presence(cid, on); });
    };
    sev.message = [this](const MessageRow& m) {
      if (ev.on_message) dispatch([this, m] { ev.on_message(to_public(m)); });
    };
    sev.status = [this](const std::string& id, MsgStatus st) {
      if (ev.on_status) dispatch([this, id, st] { ev.on_status(id, st); });
    };
    // enums are shared with the public API; no conversion needed
    sev.file_progress = [this](const FileRow& f) {
      if (ev.on_file_progress) dispatch([this, f] { ev.on_file_progress(file_progress_of(f)); });
    };
    sev.file_ready = [this](const FileRow& f) {
      if (ev.on_file_ready) {
        dispatch([this, f] {
          const auto m = db.get_message(f.msg_id);
          Message pub;
          if (m) pub = to_public(*m);
          ev.on_file_ready(f.contact_id, pub, f.local_path);
        });
      }
    };
    sev.error = [this](std::int64_t cid, std::string what) {
      if (ev.on_error) dispatch([this, cid, what = std::move(what)] { ev.on_error(cid, what); });
    };
    return sev;
  }

  void attach_channel(std::int64_t contact_id, std::unique_ptr<IChannel> ch) {
    std::lock_guard lk(mu_);
    auto crow = db.contact(contact_id);
    if (!crow) return;
    if (auto it = sessions_.find(contact_id); it != sessions_.end()) it->second->stop();
    auto s = std::make_shared<Session>(id, *crow, db, std::move(ch), session_events(),
                                       cfg.download_dir);
    sessions_[contact_id] = s;
    s->start();
  }

  std::shared_ptr<Session> established_session(std::int64_t contact_id) {
    std::lock_guard lk(mu_);
    auto it = sessions_.find(contact_id);
    if (it != sessions_.end() && it->second->established()) return it->second;
    return nullptr;
  }

  static Message to_public(const MessageRow& m);
  static FileProgress file_progress_of(const FileRow& f);
};

} // namespace shopot
