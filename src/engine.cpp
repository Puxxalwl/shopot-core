#include "engine_impl.hpp"

#ifdef SHOPOT_WITH_RTC
#include "transport/mqtt.hpp"
#include "transport/rtc.hpp"
#endif

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>

namespace shopot {

namespace {
std::int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

} // namespace

Message Engine::Impl::to_public(const MessageRow& m) {
  Message out;
  out.id = m.id;
  out.contact_id = m.contact_id;
  out.outgoing = m.outgoing;
  out.ts = m.ts;
  out.status = m.status;
  switch (m.kind) {
    case MsgKind::Text:
      out.kind = MsgKind::Text;
      out.text = m.body;
      break;
    case MsgKind::File:
    case MsgKind::Voice: {
      out.kind = m.kind;
      try {
        const auto j = nlohmann::json::parse(m.body);
        out.file_id = j.value("file", "");
        out.file_name = j.value("name", "");
        out.mime = j.value("mime", "");
        out.file_size = j.value("size", 0ULL);
      } catch (...) {
      }
      break;
    }
  }
  return out;
}

FileProgress Engine::Impl::file_progress_of(const FileRow& f) {
  FileProgress p;
  p.file_id = f.id;
  p.contact_id = f.contact_id;
  p.total_bytes = f.size;
  const double frac = f.total_chunks ? double(f.received_chunks) / f.total_chunks : 0.0;
  p.done_bytes = std::min<std::uint64_t>(f.size, std::uint64_t(frac * f.size));
  p.incoming = !f.outgoing;
  p.finished = f.state == FileState::Done;
  return p;
}

// ------------------------------------------------------------------ Engine

std::string Engine::generate_mnemonic() {
  crypto::init();
  return crypto::mnemonic_generate();
}

bool Engine::validate_mnemonic(const std::string& phrase) {
  crypto::init();
  return crypto::mnemonic_validate(phrase);
}

Engine::Engine(Config cfg, const std::string& mnemonic, Events events) {
  crypto::init();
  if (!crypto::mnemonic_validate(mnemonic))
    throw std::invalid_argument("invalid mnemonic");
  impl_ = std::make_unique<Impl>(std::move(cfg), mnemonic, std::move(events));
}

Engine::~Engine() = default;

std::string Engine::my_bundle() const { return impl_->id.bundle_b64(); }
std::string Engine::my_fingerprint() const { return impl_->id.fingerprint(); }

std::int64_t Engine::add_contact(const std::string& bundle, const std::string& name) {
  crypto::Arr<32> enc, sign;
  if (!crypto::Identity::bundle_parse(bundle, enc, sign))
    throw std::invalid_argument("bad contact bundle");
  if (enc == impl_->id.enc_pk) throw std::invalid_argument("cannot add yourself");
  return impl_->db.add_contact(enc, sign, name);
}

std::vector<Contact> Engine::contacts() const {
  std::vector<Contact> out;
  for (const ContactRow& r : impl_->db.contacts()) {
    Contact c;
    c.id = r.id;
    c.name = r.name;
    std::array<std::uint8_t, 64> raw{};
    std::memcpy(raw.data(), r.enc_pk.data(), 32);
    std::memcpy(raw.data() + 32, r.sign_pk.data(), 32);
    c.bundle = crypto::b64e(raw.data(), raw.size());
    c.fingerprint = crypto::Identity::fingerprint_of(r.enc_pk, r.sign_pk);
    std::lock_guard lk(impl_->mu_);
    auto it = impl_->sessions_.find(r.id);
    c.online = it != impl_->sessions_.end() && it->second->established();
    out.push_back(std::move(c));
  }
  return out;
}

void Engine::rename_contact(std::int64_t contact_id, const std::string& name) {
  impl_->db.rename_contact(contact_id, name);
}

void Engine::remove_contact(std::int64_t contact_id) {
  {
    std::lock_guard lk(impl_->mu_);
    if (auto it = impl_->sessions_.find(contact_id); it != impl_->sessions_.end()) {
      it->second->stop();
      impl_->sessions_.erase(it);
    }
  }
  impl_->db.remove_contact(contact_id);
}

// ------------------------------------------------------------------ signaling

#ifdef SHOPOT_WITH_RTC
std::string Engine::Impl::rtc_offer(std::int64_t contact_id, const std::string& sid) {
  auto ch = rtc_make_offer(cfg.stun_server);
  std::string code = ch->local_code();
  // stamp a per-search session id into the code: retained relay traffic from
  // older, already-dead searches must never be answered or applied
  auto j = nlohmann::json::parse(crypto::b64d(code));
  j["sid"] = sid;
  const std::string s = j.dump();
  code = crypto::b64e(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  attach_channel(contact_id, std::move(ch));
  return code;
}

std::string Engine::Impl::rtc_answer(std::int64_t contact_id, const std::string& offer_code) {
  const auto off = nlohmann::json::parse(crypto::b64d(offer_code));
  const std::string sid = off.value("sid", "");
  auto ch = rtc_make_answer(offer_code, cfg.stun_server);
  std::string code = ch->local_code();
  auto j = nlohmann::json::parse(crypto::b64d(code));
  j["sid"] = sid;  // echo: lets the initiator drop answers to stale offers
  const std::string s = j.dump();
  code = crypto::b64e(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  attach_channel(contact_id, std::move(ch));
  return code;
}

void Engine::Impl::rtc_apply(std::int64_t contact_id, const std::string& answer_code) {
  std::lock_guard lk(mu_);
  auto it = sessions_.find(contact_id);
  if (it == sessions_.end())
    throw std::runtime_error("no pending offer for this contact");
  auto* ch = dynamic_cast<RtcChannel*>(it->second->channel());
  if (!ch) throw std::runtime_error("pending channel is not RTC");
  rtc_apply_answer(*ch, answer_code);
}
#endif

std::string Engine::make_offer(std::int64_t contact_id) {
#ifdef SHOPOT_WITH_RTC
  return impl_->rtc_offer(contact_id, crypto::new_id());
#else
  (void)contact_id;
  throw std::runtime_error("built without RTC transport (SHOPOT_WITH_RTC=OFF)");
#endif
}

std::string Engine::handle_offer(std::int64_t contact_id, const std::string& offer_code) {
#ifdef SHOPOT_WITH_RTC
  return impl_->rtc_answer(contact_id, offer_code);
#else
  (void)contact_id; (void)offer_code;
  throw std::runtime_error("built without RTC transport (SHOPOT_WITH_RTC=OFF)");
#endif
}

void Engine::handle_answer(std::int64_t contact_id, const std::string& answer_code) {
#ifdef SHOPOT_WITH_RTC
  impl_->rtc_apply(contact_id, answer_code);
#else
  (void)contact_id; (void)answer_code;
  throw std::runtime_error("built without RTC transport (SHOPOT_WITH_RTC=OFF)");
#endif
}

void Engine::connect_auto(std::int64_t contact_id, std::int64_t timeout_ms) {
  if (!impl_->db.contact(contact_id)) throw std::invalid_argument("unknown contact");
  if (impl_->established_session(contact_id)) return;  // already online
#ifdef SHOPOT_WITH_RTC
  if (impl_->cfg.relays.empty())
    throw std::runtime_error("automatic rendezvous disabled: Config::relays is empty");
  {
    std::lock_guard lk(impl_->mu_);
    if (impl_->auto_inflight_.count(contact_id)) return;  // a search is already running
    // reap finished workers so the vector cannot grow unbounded
    impl_->auto_workers_.erase(
        std::remove_if(impl_->auto_workers_.begin(), impl_->auto_workers_.end(),
                       [](std::thread& t) { return !t.joinable(); }),
        impl_->auto_workers_.end());
    impl_->auto_workers_.emplace_back([impl = impl_.get(), contact_id, timeout_ms] {
      impl->auto_connect(contact_id, timeout_ms);
      {
        std::lock_guard lk(impl->mu_);
        impl->auto_inflight_.erase(contact_id);
      }
    });
    impl_->auto_inflight_.insert(contact_id);
  }
#else
  (void)timeout_ms;
  throw std::runtime_error("built without RTC transport (SHOPOT_WITH_RTC=OFF)");
#endif
}

std::string Engine::make_invite() {
  crypto::Arr<16> secret{};
  randombytes_buf(secret.data(), secret.size());
  impl_->db.invite_put(secret);
  return signal::make_invite_code(impl_->id.enc_pk, impl_->id.sign_pk, secret);
}

std::int64_t Engine::accept_invite(const std::string& code, const std::string& name) {
  const auto p = signal::parse_invite_code(code);
  if (p.sign_pk == impl_->id.sign_pk) throw std::invalid_argument("that invite is your own");
  std::string final_name = name;
  if (final_name.empty())
    final_name = "friend-" + crypto::Identity::fingerprint_of(p.enc_pk, p.sign_pk).substr(0, 8);
  const std::int64_t cid = impl_->db.add_contact(p.enc_pk, p.sign_pk, final_name);
  impl_->db.contact_invite_secret_set(cid, p.secret);
  return cid;
}

void Engine::listen_invites(std::int64_t timeout_ms) {
#ifdef SHOPOT_WITH_RTC
  if (impl_->cfg.relays.empty())
    throw std::runtime_error("automatic rendezvous disabled: Config::relays is empty");
  if (impl_->db.invites_unused().empty()) return;  // nothing to listen on
  if (impl_->invites_inflight_.exchange(true)) return;  // listener already running
  {
    std::lock_guard lk(impl_->mu_);
    impl_->auto_workers_.erase(
        std::remove_if(impl_->auto_workers_.begin(), impl_->auto_workers_.end(),
                       [](std::thread& t) { return !t.joinable(); }),
        impl_->auto_workers_.end());
    impl_->auto_workers_.emplace_back([impl = impl_.get(), timeout_ms] {
      impl->listen_invites(timeout_ms);
      impl->invites_inflight_.store(false);
    });
  }
#else
  (void)timeout_ms;
  throw std::runtime_error("built without RTC transport (SHOPOT_WITH_RTC=OFF)");
#endif
}

void Engine::Impl::listen_invites(std::int64_t timeout_ms) {
  const char* ctx = "invite-listen";
  try {
#ifdef SHOPOT_WITH_RTC
    const auto pending = db.invites_unused();
    if (pending.empty()) return;

    signal::MqttSignaling sig(cfg.relays);
    if (!sig.ok()) {
      for (int i = 0; i < 100 && !sig.ok() && !stopping_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!sig.ok()) {
      if (ev.on_error) ev.on_error(0, std::string(ctx) + ": no relay reachable");
      return;
    }

    // topic -> invite index
    std::vector<std::pair<std::string, std::size_t>> topics;
    topics.reserve(pending.size());
    for (std::size_t i = 0; i < pending.size(); ++i)
      topics.emplace_back(signal::invite_topic_for(id.sign_pk, pending[i].secret), i);
    for (const auto& [t, i] : topics) sig.subscribe(t);
    if (std::getenv("SHOPOT_SIGNAL_DEBUG"))
      std::fprintf(stderr, "[signal] listening on %zu invite topic(s)\n", topics.size());

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::vector<bool> done(pending.size(), false);
    while (!stopping_.load() && std::chrono::steady_clock::now() < deadline) {
      bool all_done = true;
      for (bool f : done) all_done = all_done && f;
      if (all_done) return;

      for (const auto& [t, p] : sig.poll(200)) {
        std::size_t idx = pending.size();
        for (const auto& [topic, i] : topics)
          if (topic == t && !done[i]) idx = i;
        if (idx == pending.size()) continue;
        try {
          const auto j = nlohmann::json::parse(
              signal::open_code(signal::invite_key_for(pending[idx].secret), p,
                                signal::kInviteMaxAgeSeconds));
          if (j.value("t", "") != "join") continue;
          crypto::Arr<32> jenc{}, jsign{};
          if (!crypto::Identity::bundle_parse(j.value("bundle", ""), jenc, jsign)) continue;
          if (jsign == id.sign_pk) continue;  // someone echoing our own bundle

          // duplicate join (idempotent re-bond) or a brand-new peer?
          std::int64_t cid = 0;
          std::string name;
          for (const auto& row : db.contacts()) {
            if (row.sign_pk == jsign) {
              cid = row.id;
              name = row.name;
              break;
            }
          }
          if (cid == 0) {
            name = "friend-" + crypto::Identity::fingerprint_of(jenc, jsign).substr(0, 8);
            cid = db.add_contact(jenc, jsign, name);
          }
          if (!db.invite_bind(pending[idx].id, cid)) continue;  // invite already bound

          const std::string welcome = std::string("{\"t\":\"welcome\",\"bundle\":\"") +
                                      id.bundle_b64() + "\",\"ts\":" +
                                      std::to_string(signal::now_unix_s()) + "}";
          sig.publish(t, signal::seal_code_ts(signal::invite_key_for(pending[idx].secret), welcome,
                                              signal::now_unix_s()));
          sig.flush_pending(5000);  // the welcome MUST leave before we move on
          done[idx] = true;
          if (ev.on_contact_added) dispatch([this, cid, name] { ev.on_contact_added(cid, name); });
          if (std::getenv("SHOPOT_SIGNAL_DEBUG"))
            std::fprintf(stderr, "[signal] invite redeemed by contact %lld\n", (long long)cid);

          // both sides know both bundles now — straight into the normal dance
          if (!established_session(cid))
            auto_connect(cid, std::chrono::duration_cast<std::chrono::milliseconds>(
                                  deadline - std::chrono::steady_clock::now())
                                  .count());
        } catch (...) {
        }  // stale/tampered/foreign join: ignore
      }
    }
#else
    (void)timeout_ms; (void)ctx;
#endif
  } catch (const std::exception& e) {
#ifdef SHOPOT_WITH_RTC
    if (ev.on_error) ev.on_error(0, std::string(ctx) + ": " + e.what());
#endif
  }
}

void Engine::Impl::auto_connect(std::int64_t contact_id, std::int64_t timeout_ms) {
  const char* ctx = "auto-connect";
  try {
#ifdef SHOPOT_WITH_RTC
    const auto c = db.contact(contact_id);
    if (!c) return;
    if (established_session(contact_id)) return;
    const crypto::Arr<32> room = crypto::room_hash(id.sign_pk, c->sign_pk);
    const std::string topic = signal::topic_for(room);
    const crypto::Arr<32> key = signal::key_for(room);
    const bool initiator = id.sign_pk < c->sign_pk;

    signal::MqttSignaling sig(cfg.relays);
    if (!sig.ok()) {  // the worker may still be dialing the first relay
      for (int i = 0; i < 100 && !sig.ok() && !stopping_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!sig.ok()) {
      if (ev.on_error) ev.on_error(contact_id, std::string(ctx) + ": no relay reachable");
      return;
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    // ---- invite prelude (acceptor side): bond over the invite topic first;
    // the inviter does not know our bundle until our sealed join arrives.
    if (const auto pending = db.contact_invite_secret(contact_id)) {
      const std::string it = signal::invite_topic_for(c->sign_pk, *pending);
      const crypto::Arr<32> ikey = signal::invite_key_for(*pending);
      sig.subscribe(it);
      if (std::getenv("SHOPOT_SIGNAL_DEBUG"))
        std::fprintf(stderr, "[signal] redeeming invite on %.16s...\n", it.c_str());
      auto next_pub = std::chrono::steady_clock::time_point::min();
      bool welcomed = established_session(contact_id) != nullptr;
      while (!stopping_.load() && !welcomed && std::chrono::steady_clock::now() < deadline) {
        for (const auto& [t, p] : sig.poll(100)) {
          (void)t;
          try {
            const auto j = nlohmann::json::parse(
                signal::open_code(ikey, p, signal::kInviteMaxAgeSeconds));
            if (j.value("t", "") != "welcome") continue;
            crypto::Arr<32> wenc{}, wsign{};
            if (!crypto::Identity::bundle_parse(j.value("bundle", ""), wenc, wsign) ||
                wsign != c->sign_pk)
              continue;  // not our inviter
            welcomed = true;
          } catch (...) {
          }
        }
        const auto now = std::chrono::steady_clock::now();
        if (!welcomed && now >= next_pub) {  // re-seal: fresh ts each attempt
          const std::string join = std::string("{\"t\":\"join\",\"bundle\":\"") +
                                   id.bundle_b64() + "\",\"ts\":" +
                                   std::to_string(signal::now_unix_s()) + "}";
          sig.publish(it, signal::seal_code_ts(ikey, join, signal::now_unix_s()));
          next_pub = now + std::chrono::seconds(10);
        }
      }
      if (!welcomed) {
        if (ev.on_error)
          ev.on_error(contact_id, std::string(ctx) + ": inviter not reached (invite stays pending)");
        return;  // the secret stays pending: the next auto retries
      }
      db.contact_invite_secret_clear(contact_id);
      if (std::getenv("SHOPOT_SIGNAL_DEBUG")) std::fprintf(stderr, "[signal] invite redeemed\n");
    }

    const std::string role_trace =
        std::string("role=") + (initiator ? "initiator" : "responder");
    if (std::getenv("SHOPOT_SIGNAL_DEBUG"))
      std::fprintf(stderr, "[signal] %s topic=%.16s...\n", role_trace.c_str(), topic.c_str());
    sig.subscribe(topic);

    auto next_pub = std::chrono::steady_clock::time_point::min();

    if (initiator) {
      const std::string sid = crypto::new_id();  // this search generation
      const std::string offer = rtc_offer(contact_id, sid);
      if (std::getenv("SHOPOT_SIGNAL_DEBUG"))
        std::fprintf(stderr, "[signal] offer ready (%zu B)\n", offer.size());
      while (!stopping_.load() && std::chrono::steady_clock::now() < deadline) {
        if (established_session(contact_id)) return;
        for (const auto& [t, p] : sig.poll(100)) {
          (void)t;
          try {
            const std::string code = signal::open_code(key, p);
            const auto j = nlohmann::json::parse(crypto::b64d(code));
            if (j.value("type", "") != "answer") continue;
            if (j.value("sid", "") != sid) continue;  // answer to a dead offer
            if (std::getenv("SHOPOT_SIGNAL_DEBUG"))
              std::fprintf(stderr, "[signal] answer accepted, applying\n");
            rtc_apply(contact_id, code);
            return;  // presence arrives from the channel itself
          } catch (...) {
          }  // foreign, tampered or stale relay traffic: ignore
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_pub) {  // re-seal so the retained blob stays fresh
          sig.publish(topic, signal::seal_code(key, offer));
          next_pub = now + std::chrono::seconds(10);
        }
      }
    } else {
      while (!stopping_.load() && std::chrono::steady_clock::now() < deadline) {
        if (established_session(contact_id)) return;
        for (const auto& [t, p] : sig.poll(100)) {
          (void)t;
          try {
            const std::string code = signal::open_code(key, p);
            const auto j = nlohmann::json::parse(crypto::b64d(code));
            if (j.value("type", "") != "offer") continue;
            if (std::getenv("SHOPOT_SIGNAL_DEBUG"))
              std::fprintf(stderr, "[signal] offer received, answering\n");
            const std::string answer = rtc_answer(contact_id, code);
            sig.publish(topic, signal::seal_code(key, answer));
            sig.flush_pending(5000);  // the answer MUST leave before we go away
            return;
          } catch (...) {
          }
        }
      }
    }
    if (!stopping_.load() && !established_session(contact_id) && ev.on_error)
      ev.on_error(contact_id, std::string(ctx) + ": peer not reached (timeout)");
#else
    (void)contact_id; (void)timeout_ms; (void)ctx;
#endif
  } catch (const std::exception& e) {
#ifdef SHOPOT_WITH_RTC
    if (ev.on_error) ev.on_error(contact_id, std::string(ctx) + ": " + e.what());
#endif
  }
}

void Engine::disconnect(std::int64_t contact_id) {
  std::lock_guard lk(impl_->mu_);
  if (auto it = impl_->sessions_.find(contact_id); it != impl_->sessions_.end()) {
    it->second->stop();
    impl_->sessions_.erase(it);
  }
}

// ------------------------------------------------------------------ messaging

std::string Engine::send_text(std::int64_t contact_id, const std::string& text) {
  if (!impl_->db.contact(contact_id)) throw std::invalid_argument("unknown contact");
  const std::string msg_id = crypto::new_id();

  MessageRow m;
  m.id = msg_id;
  m.contact_id = contact_id;
  m.outgoing = true;
  m.kind = MsgKind::Text;
  m.ts = now_ms();
  m.status = MsgStatus::Queued;
  m.body = text;
  impl_->db.put_message(m);

  const nlohmann::json j = {{"t", "text"}, {"id", msg_id}, {"ts", m.ts}, {"body", text}};
  const std::string s = j.dump();
  impl_->db.outbox_put(msg_id, contact_id, crypto::Bytes(s.begin(), s.end()));

  // live path: send exactly this payload — O(1). The outbox stays as the
  // durable retry log (full flush happens once per session establishment),
  // so a long offline queue no longer re-sends on every new message.
  if (auto sess = impl_->established_session(contact_id))
    sess->send_payload(msg_id, crypto::Bytes(s.begin(), s.end()));
  return msg_id;
}

std::string Engine::send_file(std::int64_t contact_id, const std::string& path,
                              const std::string& mime, MsgKind kind) {
  if (!impl_->db.contact(contact_id)) throw std::invalid_argument("unknown contact");
  if (kind == MsgKind::Text) kind = MsgKind::File;
  std::ifstream in(path, std::ios::binary | std::ios::ate);
  if (!in) throw std::runtime_error("cannot open file: " + path);
  const std::uint64_t size = static_cast<std::uint64_t>(in.tellg());
  in.seekg(0);

  crypto_hash_sha256_state hst;
  crypto_hash_sha256_init(&hst);
  std::vector<char> buf(1 << 20);
  while (in) {
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const auto got = in.gcount();
    if (got > 0) crypto_hash_sha256_update(&hst, reinterpret_cast<const std::uint8_t*>(buf.data()),
                                           static_cast<std::size_t>(got));
  }
  crypto::Arr<32> hash;
  crypto_hash_sha256_final(&hst, hash.data());

  const std::string msg_id = crypto::new_id();
  const std::string file_id = crypto::new_id();
  const std::uint32_t total = std::max<std::uint32_t>(
      1, static_cast<std::uint32_t>((size + kChunkSize - 1) / kChunkSize));
  const std::string name = std::filesystem::path(path).filename().string();
  const bool voice = kind == MsgKind::Voice;
  const std::int64_t ts = now_ms();

  FileRow f;
  f.id = file_id;
  f.msg_id = msg_id;
  f.contact_id = contact_id;
  f.outgoing = true;
  f.voice = voice;
  f.name = name;
  f.mime = mime;
  f.size = size;
  f.hash = hash;
  f.total_chunks = total;
  f.state = FileState::Sending;
  f.local_path = path;
  impl_->db.file_put(f);

  const nlohmann::json meta = {{"t", "file"},   {"id", msg_id}, {"ts", ts},
                               {"file", file_id}, {"name", name}, {"mime", mime},
                               {"size", size},    {"total", total},
                               {"hash", crypto::b64e(hash.data(), hash.size())},
                               {"voice", voice}};

  MessageRow m;
  m.id = msg_id;
  m.contact_id = contact_id;
  m.outgoing = true;
  m.kind = voice ? MsgKind::Voice : MsgKind::File;
  m.ts = ts;
  m.status = MsgStatus::Queued;
  m.body = meta.dump();
  impl_->db.put_message(m);

  const std::string s = meta.dump();
  impl_->db.outbox_put(msg_id, contact_id, crypto::Bytes(s.begin(), s.end()));

  // live path: meta + chunks go straight out, no full outbox re-flush
  if (auto sess = impl_->established_session(contact_id)) {
    sess->send_payload(msg_id, crypto::Bytes(s.begin(), s.end()));
    sess->send_file_now(f);
  }
  return msg_id;
}

std::vector<Message> Engine::history(std::int64_t contact_id, std::size_t limit,
                                     std::int64_t before_ts) const {
  std::vector<Message> out;
  for (const MessageRow& m : impl_->db.history(contact_id, limit, before_ts))
    out.push_back(Impl::to_public(m));
  return out;
}

void Engine::wipe() {
  {
    std::lock_guard lk(impl_->mu_);
    for (auto& [cid, s] : impl_->sessions_) s->stop();
    impl_->sessions_.clear();
  }
  impl_->db.wipe();
}

} // namespace shopot
