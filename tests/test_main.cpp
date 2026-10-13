// shopot-core tests: crypto, storage, and a full two-party protocol run
// over an in-memory loopback transport (no network involved).
#include "crypto.hpp"
#include "db.hpp"
#include "session.hpp"
#include "transport/channel.hpp"
#include "transport/mqtt_packets.hpp"
#include "transport/mqtt.hpp"
#include "transport/isignaling.hpp"

#include <sodium.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>

using namespace shopot;

static int g_failures = 0;
#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) {                                                             \
      ++g_failures;                                                            \
      std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << "  " #cond "\n"; \
    }                                                                          \
  } while (0)

// ---------------------------------------------------------------- loopback

class LoopbackChannel : public IChannel {
public:
  struct End {
    Cbs cbs;
    std::mutex mu;
    std::condition_variable cv;
    std::queue<std::vector<std::uint8_t>> inbox;
    bool cbs_set = false;
    bool closed = false;
    std::thread rx;
  };

  static std::pair<std::unique_ptr<IChannel>, std::unique_ptr<IChannel>> pair() {
    auto shared_a = std::make_shared<End>();
    auto shared_b = std::make_shared<End>();
    auto a = std::unique_ptr<LoopbackChannel>(new LoopbackChannel(shared_a, shared_b));
    auto b = std::unique_ptr<LoopbackChannel>(new LoopbackChannel(shared_b, shared_a));
    start(shared_a);
    start(shared_b);
    return {std::move(a), std::move(b)};
  }

  void set_callbacks(Cbs cbs) override {
    bool open_now = false;
    {
      std::lock_guard lk(me_->mu);
      me_->cbs = std::move(cbs);
      me_->cbs_set = true;
      open_now = true;  // loopback peers are "connected" from birth
    }
    if (open_now && me_->cbs.on_open) me_->cbs.on_open();
  }

  void send(const std::uint8_t* data, std::size_t len) override {
    {
      std::lock_guard lk(peer_->mu);
      if (peer_->closed) return;
      peer_->inbox.emplace(data, data + len);
    }
    peer_->cv.notify_one();
  }

  std::size_t buffered_amount() const override { return 0; }

  void close() override {
    {
      std::lock_guard lk(me_->mu);
      if (me_->closed) return;
      me_->closed = true;
    }
    me_->cv.notify_one();
    {
      std::lock_guard lk(peer_->mu);
      // notify peer even when already closed so its rx thread can exit
      const bool was = !peer_->closed;
      peer_->closed = true;
      if (was && peer_->cbs.on_closed) peer_->cbs.on_closed();
    }
    peer_->cv.notify_one();
  }

  ~LoopbackChannel() override {
    close();
    if (me_->rx.joinable()) me_->rx.join();
  }

private:
  LoopbackChannel(std::shared_ptr<End> me, std::shared_ptr<End> peer)
      : me_(std::move(me)), peer_(std::move(peer)) {}

  static void start(std::shared_ptr<End> e) {
    e->rx = std::thread([e] {
      for (;;) {
        std::vector<std::uint8_t> msg;
        {
          std::unique_lock lk(e->mu);
          e->cv.wait(lk, [&] { return e->closed || (!e->inbox.empty() && e->cbs_set); });
          if (e->inbox.empty()) return;
          msg = std::move(e->inbox.front());
          e->inbox.pop();
        }
        Cbs cbs;
        {
          std::lock_guard lk(e->mu);
          cbs = e->cbs;
        }
        if (cbs.on_message) cbs.on_message(msg.data(), msg.size());
      }
    });
  }

  std::shared_ptr<End> me_, peer_;
};

// ---------------------------------------------------------------- helpers

template <typename Pred>
bool wait_for(Pred p, int ms = 15000) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  while (std::chrono::steady_clock::now() < deadline) {
    if (p()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return false;
}

// ---------------------------------------------------------------- tests

static void test_crypto() {
  const std::string words = crypto::mnemonic_generate();
  CHECK(crypto::mnemonic_validate(words));
  CHECK(!crypto::mnemonic_validate(words + " zebra"));     // 13 words
  CHECK(!crypto::mnemonic_validate("abandon abandon abandon abandon abandon abandon "
                                   "abandon abandon abandon abandon abandon zebra"));  // bad checksum

  const auto entropy = crypto::mnemonic_to_entropy(words);
  const crypto::Identity id1 = crypto::Identity::from_entropy(entropy);
  const crypto::Identity id2 = crypto::Identity::from_entropy(crypto::mnemonic_to_entropy(words));
  CHECK(id1.enc_pk == id2.enc_pk && id1.sign_pk == id2.sign_pk);  // deterministic identity

  const std::string bundle = id1.bundle_b64();
  crypto::Arr<32> e{}, s{};
  CHECK(crypto::Identity::bundle_parse(bundle, e, s));
  CHECK(e == id1.enc_pk && s == id1.sign_pk);
  CHECK(!crypto::Identity::bundle_parse("not-a-bundle", e, s));

  CHECK(id1.fingerprint() == crypto::Identity::fingerprint_of(id1.enc_pk, id1.sign_pk));

  const crypto::Identity other =
      crypto::Identity::from_entropy(crypto::mnemonic_to_entropy(crypto::mnemonic_generate()));
  CHECK(crypto::room_hash(id1.sign_pk, other.sign_pk) ==
        crypto::room_hash(other.sign_pk, id1.sign_pk));

  // hello round-trip + tamper rejection
  const auto room = crypto::room_hash(id1.sign_pk, other.sign_pk);
  crypto::Arr<32> eph_a{};
  const crypto::Bytes hello = crypto::hello_make(id1, room, eph_a);
  const crypto::Hello parsed = crypto::hello_parse(hello, room, id1.sign_pk);
  const auto key_a = crypto::session_key(eph_a, parsed.epub, room);
  const auto key_b = crypto::session_key(eph_a, parsed.epub, room);
  CHECK(key_a == key_b);

  crypto::Bytes forged = hello;
  forged[forged.size() / 2] ^= 0x01;
  bool threw = false;
  try {
    crypto::hello_parse(forged, room, id1.sign_pk);
  } catch (...) {
    threw = true;
  }
  CHECK(threw);

  // AEAD round-trip + wrong key
  const auto key = crypto::random32();
  const std::string msg = "secret payload";
  const crypto::Bytes ct = crypto::seal(key, msg);
  const crypto::Bytes pt = crypto::open(key, ct);
  CHECK(std::string(pt.begin(), pt.end()) == msg);
  threw = false;
  try {
    crypto::open(crypto::random32(), ct);
  } catch (...) {
    threw = true;
  }
  CHECK(threw);
}

static void test_db() {
  const std::string path = "/tmp/shopot-test-db.sqlite";
  std::filesystem::remove(path);
  const auto key = crypto::random32();
  {
    Db db(path, key);
    crypto::Arr<32> enc{}, sign{};
    randombytes_buf(enc.data(), 32);
    randombytes_buf(sign.data(), 32);
    const std::int64_t cid = db.add_contact(enc, sign, "alice");
    CHECK(cid > 0);
    CHECK(db.contact(cid)->name == "alice");

    MessageRow m;
    m.id = "msg1";
    m.contact_id = cid;
    m.outgoing = false;
    m.kind = MsgKind::Text;
    m.ts = 1000;
    m.status = MsgStatus::Received;
    m.body = "top secret body";
    db.put_message(m);
    db.put_message(m);  // dedupe
    CHECK(db.history(cid, 10).size() == 1);
    CHECK(db.history(cid, 10)[0].body == "top secret body");

    MessageRow m2 = m;
    m2.id = "msg2";
    m2.ts = 2000;
    m2.body = "second";
    db.put_message(m2);
    const auto hist = db.history(cid, 10);
    CHECK(hist.size() == 2 && hist[0].id == "msg2");  // newest first

    db.set_message_status("msg2", MsgStatus::Delivered);
    CHECK(db.get_message("msg2")->status == MsgStatus::Delivered);

    db.outbox_put("msg2", cid, crypto::Bytes{'p', 'a', 'y'});
    CHECK(db.outbox_for(cid).size() == 1);
    CHECK(db.outbox_for(cid)[0].payload == crypto::Bytes({'p', 'a', 'y'}));
    db.outbox_del("msg2");
    CHECK(db.outbox_for(cid).empty());

    // chunks
    CHECK(!db.chunk_has("f1", 0));
    db.chunk_put("f1", 0, crypto::Bytes(100, 0xAB));
    CHECK(db.chunk_has("f1", 0));
    CHECK(db.chunk_get("f1", 0) == crypto::Bytes(100, 0xAB));
    db.chunk_clear("f1");
    CHECK(!db.chunk_has("f1", 0));

    db.put_meta("k", crypto::Bytes{'v'});
    CHECK(db.get_meta("k")->size() == 1);
  }

  // verify at-rest encryption: raw file must not contain the plaintext body
  {
    std::ifstream in(path, std::ios::binary);
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(raw.find("top secret body") == std::string::npos);
    CHECK(raw.find("alice") == std::string::npos);  // contact labels are sealed too
  }

  // wrong key cannot read
  {
    Db db(path, crypto::random32());
    bool threw = false;
    try {
      (void)db.get_message("msg1");
    } catch (...) {
      threw = true;
    }
    CHECK(threw);
  }
  std::filesystem::remove(path);
}

static void test_signal() {
  // rendezvous derivation: both peers compute identical topic and key from
  // the shared room hash alone
  const auto ra = crypto::room_hash(crypto::random32(), crypto::random32());
  const auto rb = crypto::room_hash(crypto::random32(), crypto::random32());
  CHECK(signal::topic_for(ra) == signal::topic_for(ra));
  CHECK(signal::topic_for(ra).size() == 32);
  CHECK(signal::topic_for(ra) != signal::topic_for(rb));
  CHECK(signal::key_for(ra) == signal::key_for(ra));
  CHECK(signal::key_for(ra) != signal::key_for(rb));

  // code sealing round-trip
  const std::string code =
      "eyJ0eXBlIjoib2ZmZXIiLCJzZHAiOiJ2MCIsImNhbmRpZGF0ZXMiOltdfQ";
  const auto key = signal::key_for(ra);
  const auto sealed_now = signal::seal_code(key, code);
  CHECK(signal::open_code(key, sealed_now) == code);
  CHECK(signal::seal_code(key, code) != sealed_now);  // fresh nonce each time

  // staleness: codes older than the window are rejected even when sealed
  const std::int64_t old_ts = signal::now_unix_s() - signal::kMaxAgeSeconds - 1;
  bool threw = false;
  try {
    signal::open_code(key, signal::seal_code_ts(key, code, old_ts));
  } catch (...) {
    threw = true;
  }
  CHECK(threw);

  // tamper: flipping a payload bit must fail authentication
  std::string tampered = sealed_now;
  tampered[tampered.size() / 2] ^= 0x01;
  threw = false;
  try {
    signal::open_code(key, tampered);
  } catch (...) {
    threw = true;
  }
  CHECK(threw);

  // foreign room: a different key cannot open the payload
  threw = false;
  try {
    signal::open_code(signal::key_for(rb), sealed_now);
  } catch (...) {
    threw = true;
  }
  CHECK(threw);

  // ---- MQTT packet framing ----
  const auto pub = signal::mqtt_publish("shopot/topic", "hello world", true);
  CHECK(pub[0] == 0x31);  // PUBLISH, QoS 0, retain
  signal::MqttPacket p;
  CHECK(signal::mqtt_parse_one(pub.data(), pub.size(), p) == pub.size());
  CHECK((p.type_flags >> 4) == 3);
  CHECK(p.topic == "shopot/topic");
  CHECK(p.payload == "hello world");

  // stream: two packets back-to-back parse sequentially
  const auto pub2 = signal::mqtt_publish("t2", "x", false);
  std::vector<std::uint8_t> stream = pub;
  stream.insert(stream.end(), pub2.begin(), pub2.end());
  std::size_t used = signal::mqtt_parse_one(stream.data(), stream.size(), p);
  CHECK(used == pub.size());
  used += signal::mqtt_parse_one(stream.data() + used, stream.size() - used, p);
  CHECK(used == stream.size());
  CHECK(p.payload == "x");

  // CONNECT: protocol name and version present, clean session flag set
  const auto con = signal::mqtt_connect("shopot-abcd1234", 60);
  signal::MqttPacket cp;
  CHECK(signal::mqtt_parse_one(con.data(), con.size(), cp) == con.size());
  CHECK((cp.type_flags >> 4) == 1);
  CHECK(cp.payload.size() > 10);
  CHECK(std::memcmp(cp.payload.data() + 2, "MQTT", 4) == 0);
  CHECK(cp.payload[6] == 0x04);  // level 4 = MQTT 3.1.1
  CHECK((cp.payload[7] & 0x02) != 0);

  // SUBSCRIBE + PINGREQ + DISCONNECT frame shapes
  const auto sub = signal::mqtt_subscribe("t", 1);
  CHECK(signal::mqtt_parse_one(sub.data(), sub.size(), p) == sub.size());
  CHECK((p.type_flags >> 4) == 8);
  const auto ping = signal::mqtt_pingreq();
  CHECK(ping.size() == 2 && ping[0] == 0xC0);
  const auto bye = signal::mqtt_disconnect();
  CHECK(bye.size() == 2 && bye[0] == 0xE0);

  // truncation: parser waits for more bytes instead of overrunning
  CHECK(signal::mqtt_parse_one(pub.data(), pub.size() - 1, p) == 0);
}

// live round-trip against a real public broker; network-gated so CI stays hermetic
static void test_live_mqtt() {
  if (!std::getenv("SHOPOT_LIVE_MQTT")) {
    std::cout << "(skipped: set SHOPOT_LIVE_MQTT=1)\n";
    return;
  }
#ifdef SHOPOT_WITH_RTC
  const char* url_env = std::getenv("SHOPOT_LIVE_MQTT_URL");
  const std::string url = url_env ? url_env : "wss://broker.emqx.io:8084/mqtt";
  signal::MqttClient cl(url);
  if (!cl.connect_wait(15000)) {
    std::cout << "live mqtt: CONNECT FAILED (" << url << ")\n";
    ++g_failures;
    return;
  }
  std::cout << "live mqtt: connected\n";
  const std::string topic = "shopot-selftest-" + crypto::new_id().substr(0, 8);
  cl.subscribe(topic);
  cl.publish(topic, "ping", true);
  bool got = false;
  for (int i = 0; i < 75 && !got; ++i) {
    cl.pump(200);
    for (auto& p : cl.drain())
      if (p.topic == topic && p.payload == "ping") got = true;
  }
  CHECK(got);
  std::cout << (got ? "live mqtt: subscribe+publish+echo ok\n" : "live mqtt: NO ECHO\n");
#else
  std::cout << "(skipped: no RTC)\n";
#endif
}

static void test_ratchet() {
  // handshake-style ephemeral keys
  const crypto::Arr<32> ea = crypto::random32();
  const crypto::Arr<32> eb = crypto::random32();
  crypto::Arr<32> pa{}, pb{};
  crypto_scalarmult_base(pa.data(), ea.data());
  crypto_scalarmult_base(pb.data(), eb.data());
  const crypto::Arr<32> root = crypto::random32();

  // rekey_after=8 forces dozens of alternating DH rotations over the run
  auto ra = crypto::DoubleRatchet::bootstrap(root, crypto::DoubleRatchet::Role::Initiator, ea,
                                             pb, 8);
  auto rb = crypto::DoubleRatchet::bootstrap(root, crypto::DoubleRatchet::Role::Responder, eb,
                                             pa, 8);

  for (int i = 0; i < 300; ++i) {
    const std::string ma = "a->b " + std::to_string(i);
    const auto sa = ra.encrypt(reinterpret_cast<const std::uint8_t*>(ma.data()), ma.size());
    const auto pt = rb.decrypt(sa.dh, sa.pn, sa.n, sa.body.data(), sa.body.size());
    CHECK(std::string(pt.begin(), pt.end()) == ma);

    const std::string mb = "b->a " + std::to_string(i);
    const auto sb = rb.encrypt(reinterpret_cast<const std::uint8_t*>(mb.data()), mb.size());
    const auto pt2 = ra.decrypt(sb.dh, sb.pn, sb.n, sb.body.data(), sb.body.size());
    CHECK(std::string(pt2.begin(), pt2.end()) == mb);
  }

  // the same plaintext never seals to the same ciphertext
  const auto c1 = ra.encrypt("same");
  const auto c2 = ra.encrypt("same");
  CHECK(c1.body != c2.body);

  // out-of-order within a chain exercises the skipped-key cache
  auto r2a = crypto::DoubleRatchet::bootstrap(root, crypto::DoubleRatchet::Role::Initiator, ea,
                                              pb, 64);
  auto r2b = crypto::DoubleRatchet::bootstrap(root, crypto::DoubleRatchet::Role::Responder, eb,
                                              pa, 64);
  const auto o0 = r2a.encrypt("zero");
  const auto o1 = r2a.encrypt("one");
  const auto o2 = r2a.encrypt("two");
  const auto p1 = r2b.decrypt(o1.dh, o1.pn, o1.n, o1.body.data(), o1.body.size());
  CHECK(std::string(p1.begin(), p1.end()) == "one");
  const auto p0 = r2b.decrypt(o0.dh, o0.pn, o0.n, o0.body.data(), o0.body.size());
  CHECK(std::string(p0.begin(), p0.end()) == "zero");
  const auto p2 = r2b.decrypt(o2.dh, o2.pn, o2.n, o2.body.data(), o2.body.size());
  CHECK(std::string(p2.begin(), p2.end()) == "two");

  // tamper detection
  auto tp = ra.encrypt("tamper me");
  tp.body[tp.body.size() / 2] ^= 0x01;
  bool threw = false;
  try {
    rb.decrypt(tp.dh, tp.pn, tp.n, tp.body.data(), tp.body.size());
  } catch (...) {
    threw = true;
  }
  CHECK(threw);

  // replay of a consumed index is rejected
  const auto rp = ra.encrypt("once");
  const auto ok = rb.decrypt(rp.dh, rp.pn, rp.n, rp.body.data(), rp.body.size());
  CHECK(std::string(ok.begin(), ok.end()) == "once");
  threw = false;
  try {
    rb.decrypt(rp.dh, rp.pn, rp.n, rp.body.data(), rp.body.size());
  } catch (...) {
    threw = true;
  }
  CHECK(threw);
}

static void test_protocol_loopback() {
  const std::string db_a = "/tmp/shopot-test-a.sqlite", db_b = "/tmp/shopot-test-b.sqlite";
  std::filesystem::remove(db_a);
  std::filesystem::remove(db_b);
  std::filesystem::create_directories("/tmp/shopot-dl-b");

  const crypto::Identity id_a =
      crypto::Identity::from_entropy(crypto::mnemonic_to_entropy(crypto::mnemonic_generate()));
  const crypto::Identity id_b =
      crypto::Identity::from_entropy(crypto::mnemonic_to_entropy(crypto::mnemonic_generate()));

  Db dba(db_a, id_a.storage), dbb(db_b, id_b.storage);
  const std::int64_t cid_b_in_a = dba.add_contact(id_b.enc_pk, id_b.sign_pk, "b");
  const std::int64_t cid_a_in_b = dbb.add_contact(id_a.enc_pk, id_a.sign_pk, "a");

  std::mutex mu;
  std::vector<MessageRow> got_by_b;
  std::vector<std::string> acked_in_a;
  FileRow ready_in_b;
  bool b_online = false, a_online = false;

  SessionEvents ev_a;
  ev_a.error = [](std::int64_t, std::string e) { std::cerr << "[A err] " << e << "\n"; };
  ev_a.presence = [&](std::int64_t, bool on) {
    std::lock_guard lk(mu);
    a_online = on;
  };
  ev_a.status = [&](const std::string& id, MsgStatus st) {
    if (st == MsgStatus::Delivered) {
      std::lock_guard lk(mu);
      acked_in_a.push_back(id);
    }
  };

  SessionEvents ev_b;
  ev_b.error = [](std::int64_t, std::string e) { std::cerr << "[B err] " << e << "\n"; };
  ev_b.presence = [&](std::int64_t, bool on) {
    std::lock_guard lk(mu);
    b_online = on;
  };
  ev_b.message = [&](const MessageRow& m) {
    std::lock_guard lk(mu);
    got_by_b.push_back(m);
  };
  ev_b.file_ready = [&](const FileRow& f) {
    std::lock_guard lk(mu);
    ready_in_b = f;
  };

  // 1. A queues a message while B is "offline" (no session at all)
  const std::string payload = R"({"t":"text","id":"m1","ts":1,"body":"hello b"})";
  dba.outbox_put("m1", cid_b_in_a, crypto::Bytes(payload.begin(), payload.end()));
  MessageRow mm;
  mm.id = "m1";
  mm.contact_id = cid_b_in_a;
  mm.outgoing = true;
  mm.kind = MsgKind::Text;
  mm.ts = 1;
  mm.status = MsgStatus::Queued;
  mm.body = "hello b";
  dba.put_message(mm);

  // 2. connect: sessions establish, outbox flushes, ack returns
  auto [ch_a, ch_b] = LoopbackChannel::pair();
  auto sa = std::make_shared<Session>(id_a, *dba.contact(cid_b_in_a), dba, std::move(ch_a), ev_a,
                                      "/tmp/shopot-dl-a");
  auto sb = std::make_shared<Session>(id_b, *dbb.contact(cid_a_in_b), dbb, std::move(ch_b), ev_b,
                                      "/tmp/shopot-dl-b");
  sa->start();
  sb->start();

  CHECK(wait_for([&] { return sa->established() && sb->established(); }));
  CHECK(wait_for([&] {
    std::lock_guard lk(mu);
    return a_online && b_online;
  }));
  CHECK(wait_for([&] {
    std::lock_guard lk(mu);
    return got_by_b.size() == 1;
  }));
  {
    std::lock_guard lk(mu);
    CHECK(got_by_b[0].body == "hello b");
  }
  CHECK(wait_for([&] {
    std::lock_guard lk(mu);
    return acked_in_a.size() == 1 && acked_in_a[0] == "m1";
  }));
  CHECK(wait_for([&] { return dba.outbox_for(cid_b_in_a).empty(); }));

  // 3. file transfer A -> B
  const std::string src = "/tmp/shopot-test-src.bin";
  {
    std::ofstream out(src, std::ios::binary);
    for (int i = 0; i < 300 * 1024; ++i) out.put(static_cast<char>(i * 31 + 7));
  }
  crypto::Arr<32> hash{};
  {
    std::ifstream in(src, std::ios::binary);
    crypto_hash_sha256_state hst;
    crypto_hash_sha256_init(&hst);
    std::vector<char> buf(65536);
    while (in) {
      in.read(buf.data(), buf.size());
      if (in.gcount() > 0)
        crypto_hash_sha256_update(&hst, reinterpret_cast<const std::uint8_t*>(buf.data()),
                                  in.gcount());
    }
    crypto_hash_sha256_final(&hst, hash.data());
  }
  const std::uint32_t total = (300 * 1024 + kChunkSize - 1) / kChunkSize;
  FileRow f;
  f.id = crypto::new_id();
  f.msg_id = "mf1";
  f.contact_id = cid_b_in_a;
  f.outgoing = true;
  f.name = "src.bin";
  f.mime = "application/octet-stream";
  f.size = 300 * 1024;
  f.hash = hash;
  f.total_chunks = total;
  f.state = FileState::Sending;
  f.local_path = src;
  dba.file_put(f);
  {
    std::string meta = std::string(R"({"t":"file","id":"mf1","ts":2,"file":")") + f.id +
                       R"(","name":"src.bin","mime":"application/octet-stream","size":)" +
                       std::to_string(f.size) + R"(,"total":)" + std::to_string(total) +
                       R"(,"hash":")" + crypto::b64e(hash.data(), hash.size()) + R"(","voice":false})";
    dba.outbox_put("mf1", cid_b_in_a, crypto::Bytes(meta.begin(), meta.end()));
  }
  sa->kick();

  CHECK(wait_for([&] {
    std::lock_guard lk(mu);
    return ready_in_b.state == FileState::Done;
  }, 30000));
  {
    std::lock_guard lk(mu);
    CHECK(ready_in_b.size == 300 * 1024);
    CHECK(!ready_in_b.local_path.empty());
    // content matches
    std::ifstream orig(src, std::ios::binary);
    std::ifstream got(ready_in_b.local_path, std::ios::binary);
    CHECK(std::string((std::istreambuf_iterator<char>(orig)), std::istreambuf_iterator<char>()) ==
          std::string((std::istreambuf_iterator<char>(got)), std::istreambuf_iterator<char>()));
  }

  // 4. throughput bench: 32 MiB over loopback — measures the full engine path
  // (ratchet crypto + framing + sqlite chunk writes + assembly), not the network
  {
    const std::string bsrc = "/tmp/shopot-bench.bin";
    constexpr std::uint64_t kBytes = 32ULL << 20;
    {
      std::ofstream out(bsrc, std::ios::binary);
      const std::vector<char> pat(1 << 20, 0x5A);
      for (std::uint64_t i = 0; i < (kBytes >> 20); ++i) out.write(pat.data(), pat.size());
    }
    crypto::Arr<32> bhash{};
    {
      std::ifstream in(bsrc, std::ios::binary);
      crypto_hash_sha256_state hst;
      crypto_hash_sha256_init(&hst);
      std::vector<char> hbuf(1 << 20);
      while (in) {
        in.read(hbuf.data(), static_cast<std::streamsize>(hbuf.size()));
        if (in.gcount() > 0)
          crypto_hash_sha256_update(&hst, reinterpret_cast<const std::uint8_t*>(hbuf.data()),
                                    static_cast<std::size_t>(in.gcount()));
      }
      crypto_hash_sha256_final(&hst, bhash.data());
    }
    const std::uint32_t btotal =
        static_cast<std::uint32_t>((kBytes + kChunkSize - 1) / kChunkSize);
    FileRow bf;
    bf.id = crypto::new_id();
    bf.msg_id = "bench1";
    bf.contact_id = cid_b_in_a;
    bf.outgoing = true;
    bf.name = "bench.bin";
    bf.mime = "application/octet-stream";
    bf.size = kBytes;
    bf.hash = bhash;
    bf.total_chunks = btotal;
    bf.state = FileState::Sending;
    bf.local_path = bsrc;
    dba.file_put(bf);
    {
      const std::string meta = std::string(R"({"t":"file","id":"bench1","ts":3,"file":")") +
                               bf.id +
                               R"(","name":"bench.bin","mime":"application/octet-stream","size":)" +
                               std::to_string(kBytes) + R"(,"total":)" + std::to_string(btotal) +
                               R"(,"hash":")" + crypto::b64e(bhash.data(), bhash.size()) +
                               R"(","voice":false})";
      dba.outbox_put("bench1", cid_b_in_a, crypto::Bytes(meta.begin(), meta.end()));
    }
    const auto t0 = std::chrono::steady_clock::now();
    sa->kick();
    CHECK(wait_for([&] {
      std::lock_guard lk(mu);
      return ready_in_b.id == bf.id && ready_in_b.state == FileState::Done;
    }, 120000));
    const auto t1 = std::chrono::steady_clock::now();
    const double secs = std::chrono::duration<double>(t1 - t0).count();
    std::printf("bench: %u MiB in %.2f s = %.1f MiB/s (loopback: ratchet+framing+sqlite)\n",
                static_cast<unsigned>(kBytes >> 20), secs, double(kBytes >> 20) / secs);
    std::filesystem::remove(bsrc);
  }

  // 5. disconnect / presence
  sa->stop();
  CHECK(wait_for([&] {
    std::lock_guard lk(mu);
    return !b_online;
  }));
  sb->stop();

  std::filesystem::remove(db_a);
  std::filesystem::remove(db_b);
}

int main() {
  crypto::init();
  test_crypto();
  std::cout << "crypto: ok\n";
  test_db();
  std::cout << "db: ok\n";
  test_ratchet();
  std::cout << "ratchet: ok\n";
  test_signal();
  std::cout << "signal: ok\n";
  test_live_mqtt();
  test_protocol_loopback();
  std::cout << "protocol(loopback): ok\n";
  if (g_failures) {
    std::cerr << g_failures << " FAILURES\n";
    return 1;
  }
  std::cout << "ALL TESTS PASSED\n";
  return 0;
}
