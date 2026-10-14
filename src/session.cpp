#include "session.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace shopot {

namespace {
std::int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

crypto::Bytes frame_bytes(std::uint8_t type, const crypto::Bytes& body) {
  crypto::Bytes out;
  out.reserve(body.size() + 1);
  out.push_back(type);
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

crypto::Arr<16> hex16_from_string(const std::string& hex) {
  crypto::Arr<16> out{};
  if (hex.size() != 32) throw std::runtime_error("bad file id");
  std::size_t bin_len = 0;
  if (sodium_hex2bin(out.data(), out.size(), hex.data(), hex.size(), nullptr, &bin_len, nullptr) != 0 ||
      bin_len != 16)
    throw std::runtime_error("bad file id hex");
  return out;
}

std::string safe_filename(const std::string& name) {
  std::string out;
  out.reserve(name.size());
  for (char c : name)
    out += (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_' ||
            c == ' ')
               ? c
               : '_';
  if (out.empty() || out == "." || out == "..") out = "file";
  return out;
}
} // namespace

Session::Session(const crypto::Identity& id, const ContactRow& contact, Db& db,
                 std::unique_ptr<IChannel> channel, SessionEvents ev, std::string download_dir)
    : id_(id),
      contact_(contact),
      db_(db),
      ch_(std::move(channel)),
      ev_(std::move(ev)),
      download_dir_(std::move(download_dir)) {
  room_ = crypto::room_hash(id_.sign_pk, contact_.sign_pk);
}

void Session::wire_callbacks() {
  IChannel::Cbs cbs;
  auto self = weak_from_this();
  cbs.on_open = [self] {
    if (auto s = self.lock()) s->send_hello();
  };
  cbs.on_message = [self](const std::uint8_t* d, std::size_t n) {
    if (auto s = self.lock()) s->on_channel_message(d, n);
  };
  cbs.on_closed = [self] {
    if (auto s = self.lock()) {
      const bool was = s->established_.exchange(false);
      s->closed_.store(true);
      {
        std::lock_guard lk(s->wr_mu_);
        s->wr_cv_.notify_all();
      }
      s->tx_push(TxItem{.kind = TxItem::Stop});
      if (was && s->ev_.presence) s->ev_.presence(s->contact_.id, false);
    }
  };
  cbs.on_writable = [self] {
    if (auto s = self.lock()) {
      std::lock_guard lk(s->wr_mu_);
      s->wr_cv_.notify_all();
    }
  };
  cbs.on_audio = [self](const std::uint8_t* d, std::size_t n) {
    if (auto s = self.lock()) s->on_audio_packet(d, n);
  };
  ch_->set_callbacks(std::move(cbs));
}

Session::~Session() {
  stop();
  // the ratchet wipes itself; the handshake secret only survives pre-establish
  std::lock_guard lk(mu_);
  sodium_memzero(eph_sk_.data(), eph_sk_.size());
  peer_eph_ = {};
}

void Session::start() {
  wire_callbacks();  // here, not in the ctor: callbacks need a live shared_ptr
  tx_thread_ = std::thread([this] { tx_loop(); });
}

void Session::stop() {
  if (closed_.exchange(true)) {
    if (tx_thread_.joinable()) tx_thread_.join();
    return;
  }
  ch_->close();
  tx_push(TxItem{.kind = TxItem::Stop});
  {
    std::lock_guard lk(wr_mu_);
    wr_cv_.notify_all();
  }
  if (tx_thread_.joinable()) tx_thread_.join();
  const bool was = established_.exchange(false);
  if (was && ev_.presence) ev_.presence(contact_.id, false);
}

// ------------------------------------------------------------------ handshake

void Session::send_hello() {
  try {
    crypto::Arr<32> eph{};
    crypto::Bytes hello = crypto::hello_make(id_, room_, eph);
    {
      std::lock_guard lk(mu_);
      eph_sk_ = eph;
      have_eph_ = true;
    }
    ch_->send(frame_bytes(kFrameControl, hello).data(), hello.size() + 1);
    maybe_establish();
  } catch (const std::exception& e) {
    if (ev_.error) ev_.error(contact_.id, std::string("hello: ") + e.what());
  }
}

void Session::handle_control(const std::uint8_t* data, std::size_t len) {
  if (std::getenv("SHOPOT_SESSION_DEBUG"))
    std::fprintf(stderr, "[sess] control %zu bytes\n", len);
  try {
    const crypto::Hello h =
        crypto::hello_parse(crypto::Bytes(data, data + len), room_, contact_.sign_pk);
    {
      std::lock_guard lk(mu_);
      peer_eph_ = h.epub;
      have_peer_eph_ = true;
    }
    if (!have_eph_) send_hello();  // peer spoke first: answer with our hello
    maybe_establish();
  } catch (const std::exception& e) {
    if (ev_.error) ev_.error(contact_.id, std::string("handshake rejected: ") + e.what());
  }
}

void Session::maybe_establish() {
  {
    std::lock_guard lk(mu_);
    if (established_ || !have_eph_ || !have_peer_eph_) return;
    try {
      // v2: the handshake secret becomes the ratchet root; every frame after
      // this gets its own message key, and the DH keys rotate alternately.
      const crypto::Arr<32> root = crypto::session_key(eph_sk_, peer_eph_, room_);
      const crypto::DoubleRatchet::Role role =
          id_.sign_pk < contact_.sign_pk ? crypto::DoubleRatchet::Role::Initiator
                                         : crypto::DoubleRatchet::Role::Responder;
      ratchet_ = crypto::DoubleRatchet::bootstrap(root, role, eph_sk_, peer_eph_);
    } catch (const std::exception& e) {
      if (ev_.error) ev_.error(contact_.id, std::string("key agreement: ") + e.what());
      return;
    }
    sodium_memzero(eph_sk_.data(), eph_sk_.size());
    have_eph_ = false;
  }
  established_.store(true);
  if (std::getenv("SHOPOT_SESSION_DEBUG")) std::fprintf(stderr, "[sess] established\n");
  if (ev_.presence) ev_.presence(contact_.id, true);
  kick();  // flush outbox + pending files (establishment is the only full flush)
}

// ------------------------------------------------------------------ v2 frames
// body layout for 0x11/0x12: dh(32) || pn(4BE) || n(4BE) || nonce(24) || ct

crypto::Bytes Session::ratchet_seal(const std::uint8_t* data, std::size_t len) {
  std::lock_guard lk(mu_);
  const crypto::DoubleRatchet::Sealed s = ratchet_.encrypt(data, len);
  crypto::Bytes out;
  out.reserve(40 + s.body.size());
  out.insert(out.end(), s.dh.begin(), s.dh.end());
  for (int b = 3; b >= 0; --b) out.push_back(static_cast<std::uint8_t>(s.pn >> (b * 8)));
  for (int b = 3; b >= 0; --b) out.push_back(static_cast<std::uint8_t>(s.n >> (b * 8)));
  out.insert(out.end(), s.body.begin(), s.body.end());
  return out;
}

crypto::Bytes Session::ratchet_open(const std::uint8_t* data, std::size_t len) {
  constexpr std::size_t kHdr = 40;
  if (len < kHdr + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
    throw std::runtime_error("frame too short");
  crypto::Arr<32> dh;
  std::memcpy(dh.data(), data, 32);
  const std::uint32_t pn = (static_cast<std::uint32_t>(data[32]) << 24) |
                           (static_cast<std::uint32_t>(data[33]) << 16) |
                           (static_cast<std::uint32_t>(data[34]) << 8) |
                           static_cast<std::uint32_t>(data[35]);
  const std::uint32_t n = (static_cast<std::uint32_t>(data[36]) << 24) |
                          (static_cast<std::uint32_t>(data[37]) << 16) |
                          (static_cast<std::uint32_t>(data[38]) << 8) |
                          static_cast<std::uint32_t>(data[39]);
  std::lock_guard lk(mu_);
  return ratchet_.decrypt(dh, pn, n, data + kHdr, len - kHdr);
}

// ------------------------------------------------------------------ rx

void Session::on_channel_message(const std::uint8_t* data, std::size_t len) {
  if (len < 1 || closed_) return;
  switch (data[0]) {
    case kFrameControl:
      handle_control(data + 1, len - 1);
      break;
    case kFrameEnvelope:
      if (established_) handle_envelope(data + 1, len - 1);
      break;
    case kFrameChunk:
      if (established_) handle_chunk(data + 1, len - 1);
      break;
    default:
      break;
  }
}

void Session::handle_envelope(const std::uint8_t* data, std::size_t len) {
  crypto::Bytes plain;
  try {
    plain = ratchet_open(data, len);
  } catch (...) {
    return;  // forged/corrupt frame or ratchet desync: drop silently
  }
  nlohmann::json j;
  try {
    j = nlohmann::json::parse(plain.begin(), plain.end());
  } catch (...) {
    return;
  }
  const std::string t = j.value("t", "");

  if (t == "ack") {
    const std::string ref = j.value("ref", "");
    db_.outbox_del(ref);
    db_.set_message_status(ref, MsgStatus::Delivered);
    if (ev_.status) ev_.status(ref, MsgStatus::Delivered);
    return;
  }

  if (t == "fdone") {
    const std::string fid = j.value("file", "");
    if (auto f = db_.file_get(fid)) {
      db_.file_set_state(fid, FileState::Done);
      f->state = FileState::Done;
      if (ev_.file_progress) ev_.file_progress(*f);
    }
    return;
  }

  if (t == "text" || t == "file") {
    const std::string id = j.value("id", "");
    if (id.empty()) return;
    ack(id);
    const bool fresh = !db_.has_message(id);
    if (!fresh) return;  // duplicate delivery (sender re-flushed): ack sent above, done

    MessageRow m;
    m.id = id;
    m.contact_id = contact_.id;
    m.outgoing = false;
    m.ts = j.value("ts", now_ms());
    m.status = MsgStatus::Received;

    if (t == "text") {
      m.kind = MsgKind::Text;
      m.body = j.value("body", "");
    } else {
      m.kind = j.value("voice", false) ? MsgKind::Voice : MsgKind::File;
      FileRow f;
      f.id = j.value("file", "");
      f.msg_id = id;
      f.contact_id = contact_.id;
      f.outgoing = false;
      f.voice = j.value("voice", false);
      f.name = j.value("name", "file");
      f.mime = j.value("mime", "application/octet-stream");
      f.size = j.value("size", 0ULL);
      f.total_chunks = j.value("total", 0U);
      f.state = FileState::Receiving;
      const crypto::Bytes h = crypto::b64d(j.value("hash", ""));
      if (h.size() != 32 || f.id.size() != 32 || f.total_chunks == 0) return;
      std::memcpy(f.hash.data(), h.data(), 32);
      db_.file_put(f);
      m.body = j.dump();
    }
    db_.put_message(m);
    if (ev_.message) ev_.message(m);
    return;
  }

  if (t == "call") {
    const std::string act = j.value("act", "");
    const std::string cid = j.value("id", "");
    if (act.empty() || cid.empty()) return;
    if (ev_.call_signal) ev_.call_signal(act, cid);
    return;
  }
}

// ------------------------------------------------------------------ calls

void Session::set_call(const std::string& call_id, const char* role) {
  std::lock_guard lk(call_mu_);
  call_id_ = call_id;
  call_role_ = role && *role ? role[0] : 0;
}

void Session::clear_call() {
  std::lock_guard lk(call_mu_);
  call_id_.clear();
  call_role_ = 0;
}

void Session::send_call_signal(const std::string& act, const std::string& call_id) {
  nlohmann::json j;
  j["t"] = "call";
  j["act"] = act;
  j["id"] = call_id;
  const std::string s = j.dump();
  const crypto::Bytes plain(s.begin(), s.end());
  tx_push(TxItem{.kind = TxItem::Frame, .frame = frame_bytes(kFrameEnvelope, ratchet_seal(
      plain.data(), plain.size()))});
}

void Session::send_audio_packet(const std::uint8_t* data, std::size_t len) {
  std::string call_id;
  char role = 0;
  {
    std::lock_guard lk(call_mu_);
    call_id = call_id_;
    role = call_role_;
  }
  if (call_id.empty() || role == 0 || len == 0) return;
  const crypto::Arr<32> key = crypto::call_key_for(room_, call_id, role);
  crypto::Bytes out;
  out.reserve(crypto_secretbox_NONCEBYTES + len + crypto_secretbox_MACBYTES);
  crypto::Arr<24> nonce{};
  randombytes_buf(nonce.data(), nonce.size());
  out.insert(out.end(), nonce.begin(), nonce.end());
  crypto::Bytes box(len + crypto_secretbox_MACBYTES);
  crypto_secretbox_easy(box.data(), data, len, nonce.data(), key.data());
  out.insert(out.end(), box.begin(), box.end());
  ch_->send_audio(out.data(), out.size());
}

void Session::on_audio_packet(const std::uint8_t* data, std::size_t len) {
  std::string call_id;
  char role = 0;
  {
    std::lock_guard lk(call_mu_);
    call_id = call_id_;
    role = call_role_;
  }
  if (call_id.empty() || role == 0) return;  // no active call: drop late frames
  constexpr std::size_t kHdr = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
  if (len < kHdr + 8) return;  // less than half a 20ms frame: junk
  const char peer_role = role == 'i' ? 'r' : 'i';
  const crypto::Arr<32> key = crypto::call_key_for(room_, call_id, peer_role);
  crypto::Bytes plain(len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
  if (crypto_secretbox_open_easy(plain.data(), data + crypto_secretbox_NONCEBYTES,
                                 len - crypto_secretbox_NONCEBYTES, data, key.data()) != 0)
    return;  // forged/dropped-key frame: drop silently
  if (ev_.call_audio) ev_.call_audio(plain.data(), plain.size());
}

void Session::handle_chunk(const std::uint8_t* data, std::size_t len) {
  // v2: the AEAD covers file_id(16) || idx(4BE) || chunk data — tampered
  // routing fields are rejected by authentication instead of corrupting slots
  crypto::Bytes plain;
  try {
    plain = ratchet_open(data, len);
  } catch (...) {
    return;
  }
  if (plain.size() < 20 || plain.size() - 20 > kChunkSize) return;

  crypto::Arr<16> fid_raw;
  std::memcpy(fid_raw.data(), plain.data(), 16);
  const std::uint32_t idx = (static_cast<std::uint32_t>(plain[16]) << 24) |
                            (static_cast<std::uint32_t>(plain[17]) << 16) |
                            (static_cast<std::uint32_t>(plain[18]) << 8) |
                            static_cast<std::uint32_t>(plain[19]);
  const std::string fid = crypto::hex_lower(fid_raw.data(), fid_raw.size());

  auto f = db_.file_get(fid);
  if (!f || f->state != FileState::Receiving || idx >= f->total_chunks) return;

  const crypto::Bytes chunk(plain.begin() + 20, plain.end());
  const bool is_new = !db_.chunk_has(fid, idx);  // sender may restart a transfer
  db_.chunk_put(fid, idx, chunk);
  if (!is_new) return;
  const std::uint32_t have = f->received_chunks + 1;
  f->received_chunks = have;
  db_.file_set_progress(fid, have);
  if (have % 16 == 0 && ev_.file_progress) ev_.file_progress(*f);

  if (have >= f->total_chunks) complete_file(*f);
}

void Session::complete_file(FileRow& f) {
  try {
    // assemble, verify hash, move to the download dir
    crypto_hash_sha256_state hst;
    crypto_hash_sha256_init(&hst);
    std::vector<crypto::Bytes> chunks;
    chunks.reserve(f.total_chunks);
    for (std::uint32_t i = 0; i < f.total_chunks; ++i) {
      crypto::Bytes c = db_.chunk_get(f.id, i);
      crypto_hash_sha256_update(&hst, c.data(), c.size());
      chunks.push_back(std::move(c));
    }
    crypto::Arr<32> digest;
    crypto_hash_sha256_final(&hst, digest.data());
    if (sodium_memcmp(digest.data(), f.hash.data(), 32) != 0)
      throw std::runtime_error("file hash mismatch");

    std::filesystem::create_directories(download_dir_);
    std::filesystem::path dest =
        std::filesystem::path(download_dir_) / (f.id.substr(0, 8) + "-" + safe_filename(f.name));
    std::ofstream out(dest, std::ios::binary | std::ios::trunc);
    for (const auto& c : chunks)
      out.write(reinterpret_cast<const char*>(c.data()), static_cast<std::streamsize>(c.size()));
    out.close();

    db_.file_set_state(f.id, FileState::Done, dest.string());
    db_.chunk_clear(f.id);
    f.state = FileState::Done;
    f.local_path = dest.string();

    // tell the sender
    const nlohmann::json j = {{"t", "fdone"}, {"file", f.id}};
    const std::string s = j.dump();
    try {
      const crypto::Bytes sealed =
          ratchet_seal(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
      tx_push(TxItem{.kind = TxItem::Frame, .frame = frame_bytes(kFrameEnvelope, sealed)});
    } catch (...) {
    }

    if (ev_.file_progress) ev_.file_progress(f);
    if (ev_.file_ready) ev_.file_ready(f);
  } catch (const std::exception& e) {
    db_.file_set_state(f.id, FileState::Failed);
    if (ev_.error) ev_.error(contact_.id, std::string("file receive: ") + e.what());
  }
}

// ------------------------------------------------------------------ tx

void Session::ack(const std::string& ref) {
  if (!established_.load()) return;
  const nlohmann::json j = {{"t", "ack"}, {"ref", ref}};
  const std::string s = j.dump();
  crypto::Bytes sealed;
  try {
    sealed = ratchet_seal(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  } catch (...) {
    return;
  }
  tx_push(TxItem{.kind = TxItem::Frame, .frame = frame_bytes(kFrameEnvelope, sealed)});
}

void Session::send_payload(const std::string& msg_id, const crypto::Bytes& envelope_plain) {
  if (!established_.load()) return;
  crypto::Bytes sealed;
  try {
    sealed = ratchet_seal(envelope_plain.data(), envelope_plain.size());
  } catch (...) {
    return;  // ratchet unavailable: payload stays in the outbox for the next flush
  }
  tx_push(TxItem{.kind = TxItem::Frame, .frame = frame_bytes(kFrameEnvelope, sealed)});
  db_.set_message_status(msg_id, MsgStatus::Sent);
  if (ev_.status) ev_.status(msg_id, MsgStatus::Sent);
}

void Session::kick() { tx_push(TxItem{.kind = TxItem::Flush}); }

void Session::tx_push(TxItem item) {
  {
    std::lock_guard lk(tx_mu_);
    tx_q_.push(std::move(item));
  }
  tx_cv_.notify_one();
}

void Session::tx_loop() {
  for (;;) {
    TxItem item;
    {
      std::unique_lock lk(tx_mu_);
      tx_cv_.wait(lk, [&] { return !tx_q_.empty(); });
      item = std::move(tx_q_.front());
      tx_q_.pop();
    }
    if (item.kind == TxItem::Stop || closed_) return;
    try {
      switch (item.kind) {
        case TxItem::Frame:
          ch_->send(item.frame.data(), item.frame.size());
          break;
        case TxItem::Flush:
          do_flush();
          break;
        case TxItem::PumpFile:
          do_pump(item.file);
          break;
        default:
          break;
      }
    } catch (const std::exception& e) {
      if (ev_.error) ev_.error(contact_.id, std::string("tx: ") + e.what());
    }
  }
}

void Session::do_flush() {
  if (!established_) return;
  for (const OutboxRow& row : db_.outbox_for(contact_.id))
    send_payload(row.msg_id, row.payload);
  for (const FileRow& f : db_.files_pending_send(contact_.id))
    tx_push(TxItem{.kind = TxItem::PumpFile, .file = f});
}

void Session::wait_writable() {
  std::unique_lock lk(wr_mu_);
  wr_cv_.wait_for(lk, std::chrono::milliseconds(50), [&] {
    return closed_.load() || ch_->buffered_amount() < kBufferedLow;
  });
}

void Session::do_pump(const FileRow& file) {
  std::ifstream in(file.local_path, std::ios::binary);
  if (!in) {
    db_.file_set_state(file.id, FileState::Failed);
    if (ev_.error) ev_.error(contact_.id, "cannot open " + file.local_path);
    return;
  }
  const crypto::Arr<16> fid_raw = hex16_from_string(file.id);
  crypto::Bytes buf(kChunkSize);
  for (std::uint32_t i = 0; i < file.total_chunks && !closed_; ++i) {
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(kChunkSize));
    const std::size_t got = static_cast<std::size_t>(in.gcount());
    if (got == 0 && i + 1 < file.total_chunks) break;  // truncated source

    // v2: fid and idx travel inside the AEAD as part of the plaintext
    crypto::Bytes inner;
    inner.reserve(20 + got);
    inner.insert(inner.end(), fid_raw.begin(), fid_raw.end());
    for (int b = 3; b >= 0; --b) inner.push_back(static_cast<std::uint8_t>(i >> (b * 8)));
    inner.insert(inner.end(), buf.begin(), buf.begin() + got);

    if (!established_.load()) return;
    crypto::Bytes sealed;
    try {
      sealed = ratchet_seal(inner.data(), inner.size());
    } catch (...) {
      return;
    }
    crypto::Bytes frame;
    frame.reserve(1 + sealed.size());
    frame.push_back(kFrameChunk);
    frame.insert(frame.end(), sealed.begin(), sealed.end());

    while (ch_->buffered_amount() > kBufferedHigh && !closed_) wait_writable();
    if (closed_) return;
    ch_->send(frame.data(), frame.size());

    if ((i + 1) % 16 == 0 || i + 1 == file.total_chunks) {
      FileRow prog = file;
      prog.received_chunks = i + 1;
      if (ev_.file_progress) ev_.file_progress(prog);
    }
  }
  if (!closed_) db_.file_set_state(file.id, FileState::Done);
}

} // namespace shopot
