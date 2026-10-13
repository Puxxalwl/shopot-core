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
std::string Engine::Impl::rtc_offer(std::int64_t contact_id) {
  auto ch = rtc_make_offer(cfg.stun_server);
  std::string code = ch->local_code();
  attach_channel(contact_id, std::move(ch));
  return code;
}

std::string Engine::Impl::rtc_answer(std::int64_t contact_id, const std::string& offer_code) {
  auto ch = rtc_make_answer(offer_code, cfg.stun_server);
  std::string code = ch->local_code();
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
  return impl_->rtc_offer(contact_id);
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
    // reap finished workers so the vector cannot grow unbounded
    impl_->auto_workers_.erase(
        std::remove_if(impl_->auto_workers_.begin(), impl_->auto_workers_.end(),
                       [](std::thread& t) { return !t.joinable(); }),
        impl_->auto_workers_.end());
    impl_->auto_workers_.emplace_back(
        [impl = impl_.get(), contact_id, timeout_ms] { impl->auto_connect(contact_id, timeout_ms); });
  }
#else
  (void)timeout_ms;
  throw std::runtime_error("built without RTC transport (SHOPOT_WITH_RTC=OFF)");
#endif
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
    if (std::getenv("SHOPOT_SIGNAL_DEBUG"))
      std::fprintf(stderr, "[signal] role=%s topic=%.16s...\n", initiator ? "initiator" : "responder",
                   topic.c_str());

    signal::MqttSignaling sig(cfg.relays);
    if (!sig.ok()) {  // the worker may still be dialing the first relay
      for (int i = 0; i < 100 && !sig.ok() && !stopping_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!sig.ok()) {
      if (ev.on_error) ev.on_error(contact_id, std::string(ctx) + ": no relay reachable");
      return;
    }
    sig.subscribe(topic);

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    auto next_pub = std::chrono::steady_clock::time_point::min();

    if (initiator) {
      const std::string offer = rtc_offer(contact_id);
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
