#pragma once

#include "crypto.hpp"
#include "db.hpp"
#include "session.hpp"
#include "shopot/shopot.hpp"
#include "transport/isignaling.hpp"

#include <sodium.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>

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
  std::vector<std::thread> auto_workers_;  // rendezvous workers, joined in ~Impl
  std::unordered_set<std::int64_t> auto_inflight_;  // contacts with a live search
  std::atomic<bool> invites_inflight_{false};       // one invite listener at a time
  std::atomic<bool> stopping_{false};

  // calls: one per contact; guarded by mu_ (never held across user callbacks)
  struct Call {
    std::string id;
    CallState state = CallState::Idle;
    std::string reason;
  };
  std::unordered_map<std::int64_t, Call> calls_;
  std::vector<std::thread> call_timers_;  // ring timeout watchers

  Impl(Config c, const std::string& mnemonic, Events events)
      : cfg(std::move(c)),
        ev(std::move(events)),
        id(crypto::Identity::from_entropy(crypto::mnemonic_to_entropy(mnemonic))),
        db(cfg.db_path, id.storage) {
    eq_thread_ = std::thread([this] { dispatcher_loop(); });
  }

  ~Impl() {
    stopping_.store(true);  // tell auto-connect workers and call timers to bail
    for (auto& t : call_timers_)
      if (t.joinable()) t.join();
    for (auto& w : auto_workers_)
      if (w.joinable()) w.join();
    {
      std::lock_guard lk(mu_);
      for (auto& [cid, s] : sessions_) s->stop();
      sessions_.clear();
    }
    eq_cv_.notify_one();
    if (eq_thread_.joinable()) eq_thread_.join();
    // identity secrets never outlive the engine: wipe X25519/Ed25519 keys
    // and the DB storage key
    sodium_memzero(id.enc_sk.data(), id.enc_sk.size());
    sodium_memzero(id.sign_sk.data(), id.sign_sk.size());
    sodium_memzero(id.storage.data(), id.storage.size());
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
    // attach_channel sets this while the events for one contact are built
    const std::int64_t self_contact = wiring_contact_;
    sev.call_signal = [this, self_contact](const std::string& act, const std::string& call_id) {
      dispatch([this, self_contact, act, call_id] {
        handle_call_signal(self_contact, act, call_id);
      });
    };
    sev.call_audio = [this, self_contact](const std::uint8_t* d, std::size_t n) {
      if (!ev.on_call_audio || self_contact < 0) return;
      // copy the bytes; the lane frees them as soon as we return
      std::vector<std::uint8_t> buf(d, d + n);
      dispatch([this, self_contact, buf] {
        bool active = false;
        {
          std::lock_guard lk(mu_);
          const auto it = calls_.find(self_contact);
          active = it != calls_.end() && it->second.state == CallState::Active;
        }
        if (active) ev.on_call_audio(self_contact, buf.data(), buf.size());
      });
    };
    return sev;
  }

  std::atomic<std::int64_t> wiring_contact_{-1};  // set while attach_channel builds a session

  void set_call_state(std::int64_t cid, CallState st, const std::string& reason,
                      const std::string& call_id);
  void handle_call_signal(std::int64_t contact_id, const std::string& act,
                          const std::string& call_id);

#ifdef SHOPOT_WITH_RTC
  // programmatic variants of the manual signaling dance (used by connect_auto)
  std::string rtc_offer(std::int64_t contact_id, const std::string& sid);
  std::string rtc_answer(std::int64_t contact_id, const std::string& offer_code);
  void rtc_apply(std::int64_t contact_id, const std::string& answer_code);
#endif
  void auto_connect(std::int64_t contact_id, std::int64_t timeout_ms);
  void listen_invites(std::int64_t timeout_ms);

  void attach_channel(std::int64_t contact_id, std::unique_ptr<IChannel> ch) {
    wiring_contact_ = contact_id;  // read by session_events() only here
    SessionEvents sev = session_events();
    wiring_contact_ = -1;
    std::lock_guard lk(mu_);
    auto crow = db.contact(contact_id);
    if (!crow) return;
    if (auto it = sessions_.find(contact_id); it != sessions_.end()) it->second->stop();
    auto s = std::make_shared<Session>(id, *crow, db, std::move(ch), std::move(sev),
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
