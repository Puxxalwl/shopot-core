#include "db.hpp"

#include <sqlite3.h>
#include <sodium.h>

#include <chrono>
#include <cstring>
#include <stdexcept>

namespace shopot {

namespace {
std::int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

struct Stmt {
  Stmt() = default;
  sqlite3_stmt* p = nullptr;
  ~Stmt() { sqlite3_finalize(p); }
  Stmt(const Stmt&) = delete;
  Stmt& operator=(const Stmt&) = delete;
};

void bind_blob(sqlite3_stmt* st, int i, const std::uint8_t* d, std::size_t n) {
  sqlite3_bind_blob(st, i, d, static_cast<int>(n), SQLITE_TRANSIENT);
}
void bind_text(sqlite3_stmt* st, int i, const std::string& s) {
  sqlite3_bind_text(st, i, s.data(), static_cast<int>(s.size()), SQLITE_TRANSIENT);
}
} // namespace

Db::Db(const std::string& path, const crypto::Arr<32>& storage_key) : key_(storage_key) {
  if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK)
    throw std::runtime_error(std::string("sqlite open failed: ") + sqlite3_errmsg(db_));
  exec("PRAGMA journal_mode=WAL;");
  exec("PRAGMA busy_timeout=5000;");
  exec("PRAGMA synchronous=NORMAL;");
  exec("PRAGMA foreign_keys=ON;");
  exec(R"SQL(
CREATE TABLE IF NOT EXISTS meta(
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS contacts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  enc_pub BLOB NOT NULL UNIQUE,
  sign_pub BLOB NOT NULL,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages(
  id TEXT PRIMARY KEY,
  contact_id INTEGER NOT NULL,
  outgoing INTEGER NOT NULL,
  kind INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  status INTEGER NOT NULL,
  body BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_id, ts);
CREATE TABLE IF NOT EXISTS outbox(
  msg_id TEXT PRIMARY KEY,
  contact_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS files(
  id TEXT PRIMARY KEY,
  msg_id TEXT NOT NULL,
  contact_id INTEGER NOT NULL,
  outgoing INTEGER NOT NULL,
  voice INTEGER NOT NULL,
  name TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  hash BLOB NOT NULL,
  total_chunks INTEGER NOT NULL,
  received_chunks INTEGER NOT NULL,
  state INTEGER NOT NULL,
  local_path TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS chunks(
  file_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  data BLOB NOT NULL,
  PRIMARY KEY(file_id, idx));
)SQL");
}

Db::~Db() {
  sqlite3_close(db_);
  sodium_memzero(key_.data(), key_.size());  // the storage key never outlives the store
}

void Db::exec(const char* sql) {
  char* err = nullptr;
  if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
    std::string msg = err ? err : "unknown";
    sqlite3_free(err);
    throw std::runtime_error("sqlite: " + msg);
  }
}

// ------------------------------------------------------------------ meta

void Db::put_meta(const std::string& key, const crypto::Bytes& plaintext) {
  const crypto::Bytes sealed = seal_col(plaintext.data(), plaintext.size());
  Stmt st;
  sqlite3_prepare_v2(db_, "INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", -1, &st.p, nullptr);
  bind_text(st.p, 1, key);
  bind_blob(st.p, 2, sealed.data(), sealed.size());
  if (sqlite3_step(st.p) != SQLITE_DONE) throw std::runtime_error("meta put failed");
}

std::optional<crypto::Bytes> Db::get_meta(const std::string& key) {
  Stmt st;
  sqlite3_prepare_v2(db_, "SELECT v FROM meta WHERE k=?", -1, &st.p, nullptr);
  bind_text(st.p, 1, key);
  if (sqlite3_step(st.p) != SQLITE_ROW) return std::nullopt;
  crypto::Bytes sealed(static_cast<const std::uint8_t*>(sqlite3_column_blob(st.p, 0)),
                       static_cast<const std::uint8_t*>(sqlite3_column_blob(st.p, 0)) +
                           sqlite3_column_bytes(st.p, 0));
  return open_col(sealed);
}

// ------------------------------------------------------------------ contacts

std::int64_t Db::add_contact(const crypto::Arr<32>& enc_pk, const crypto::Arr<32>& sign_pk,
                             const std::string& name) {
  // return existing contact for the same key (idempotent add)
  {
    Stmt st;
    sqlite3_prepare_v2(db_, "SELECT id FROM contacts WHERE enc_pub=?", -1, &st.p, nullptr);
    bind_blob(st.p, 1, enc_pk.data(), enc_pk.size());
    if (sqlite3_step(st.p) == SQLITE_ROW) return sqlite3_column_int64(st.p, 0);
  }
  Stmt st;
  sqlite3_prepare_v2(db_,
                     "INSERT INTO contacts(enc_pub,sign_pub,name,created_at) VALUES(?,?,?,?)",
                     -1, &st.p, nullptr);
  bind_blob(st.p, 1, enc_pk.data(), enc_pk.size());
  bind_blob(st.p, 2, sign_pk.data(), sign_pk.size());
  bind_text(st.p, 3, name);
  sqlite3_bind_int64(st.p, 4, now_ms());
  if (sqlite3_step(st.p) != SQLITE_DONE) throw std::runtime_error("add_contact failed");
  return sqlite3_last_insert_rowid(db_);
}

std::vector<ContactRow> Db::contacts() {
  Stmt st;
  sqlite3_prepare_v2(db_, "SELECT id,enc_pub,sign_pub,name,created_at FROM contacts ORDER BY name",
                     -1, &st.p, nullptr);
  std::vector<ContactRow> out;
  while (sqlite3_step(st.p) == SQLITE_ROW) {
    ContactRow c;
    c.id = sqlite3_column_int64(st.p, 0);
    std::memcpy(c.enc_pk.data(), sqlite3_column_blob(st.p, 1), 32);
    std::memcpy(c.sign_pk.data(), sqlite3_column_blob(st.p, 2), 32);
    c.name = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 3));
    c.created_at = sqlite3_column_int64(st.p, 4);
    out.push_back(std::move(c));
  }
  return out;
}

std::optional<ContactRow> Db::contact(std::int64_t id) {
  Stmt st;
  sqlite3_prepare_v2(db_, "SELECT id,enc_pub,sign_pub,name,created_at FROM contacts WHERE id=?",
                     -1, &st.p, nullptr);
  sqlite3_bind_int64(st.p, 1, id);
  if (sqlite3_step(st.p) != SQLITE_ROW) return std::nullopt;
  ContactRow c;
  c.id = sqlite3_column_int64(st.p, 0);
  std::memcpy(c.enc_pk.data(), sqlite3_column_blob(st.p, 1), 32);
  std::memcpy(c.sign_pk.data(), sqlite3_column_blob(st.p, 2), 32);
  c.name = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 3));
  c.created_at = sqlite3_column_int64(st.p, 4);
  return c;
}

void Db::rename_contact(std::int64_t id, const std::string& name) {
  Stmt st;
  sqlite3_prepare_v2(db_, "UPDATE contacts SET name=? WHERE id=?", -1, &st.p, nullptr);
  bind_text(st.p, 1, name);
  sqlite3_bind_int64(st.p, 2, id);
  sqlite3_step(st.p);
}

void Db::remove_contact(std::int64_t id) {
  for (const char* sql :
       {"DELETE FROM contacts WHERE id=?1", "DELETE FROM messages WHERE contact_id=?1",
        "DELETE FROM outbox WHERE contact_id=?1", "DELETE FROM files WHERE contact_id=?1"}) {
    Stmt st;
    sqlite3_prepare_v2(db_, sql, -1, &st.p, nullptr);
    sqlite3_bind_int64(st.p, 1, id);
    sqlite3_step(st.p);
  }
}

// ------------------------------------------------------------------ messages

void Db::put_message(const MessageRow& m) {
  const crypto::Bytes sealed = seal_col(reinterpret_cast<const std::uint8_t*>(m.body.data()),
                                        m.body.size());
  Stmt st;
  sqlite3_prepare_v2(db_,
                     "INSERT OR IGNORE INTO messages(id,contact_id,outgoing,kind,ts,status,body)"
                     " VALUES(?,?,?,?,?,?,?)",
                     -1, &st.p, nullptr);
  bind_text(st.p, 1, m.id);
  sqlite3_bind_int64(st.p, 2, m.contact_id);
  sqlite3_bind_int(st.p, 3, m.outgoing ? 1 : 0);
  sqlite3_bind_int(st.p, 4, static_cast<int>(m.kind));
  sqlite3_bind_int64(st.p, 5, m.ts);
  sqlite3_bind_int(st.p, 6, static_cast<int>(m.status));
  bind_blob(st.p, 7, sealed.data(), sealed.size());
  if (sqlite3_step(st.p) != SQLITE_DONE) throw std::runtime_error("put_message failed");
}

bool Db::has_message(const std::string& id) {
  Stmt st;
  sqlite3_prepare_v2(db_, "SELECT 1 FROM messages WHERE id=?", -1, &st.p, nullptr);
  bind_text(st.p, 1, id);
  return sqlite3_step(st.p) == SQLITE_ROW;
}

std::optional<MessageRow> Db::get_message(const std::string& id) {
  Stmt st;
  sqlite3_prepare_v2(db_,
                     "SELECT contact_id,outgoing,kind,ts,status,body FROM messages WHERE id=?",
                     -1, &st.p, nullptr);
  bind_text(st.p, 1, id);
  if (sqlite3_step(st.p) != SQLITE_ROW) return std::nullopt;
  MessageRow m;
  m.id = id;
  m.contact_id = sqlite3_column_int64(st.p, 0);
  m.outgoing = sqlite3_column_int(st.p, 1) != 0;
  m.kind = static_cast<MsgKind>(sqlite3_column_int(st.p, 2));
  m.ts = sqlite3_column_int64(st.p, 3);
  m.status = static_cast<MsgStatus>(sqlite3_column_int(st.p, 4));
  const auto* blob = static_cast<const std::uint8_t*>(sqlite3_column_blob(st.p, 5));
  crypto::Bytes plain = open_col(crypto::Bytes(blob, blob + sqlite3_column_bytes(st.p, 5)));
  m.body.assign(reinterpret_cast<const char*>(plain.data()), plain.size());
  return m;
}

std::vector<MessageRow> Db::history(std::int64_t contact_id, std::size_t limit,
                                    std::int64_t before_ts) {
  Stmt st;
  sqlite3_prepare_v2(db_,
                     "SELECT id,outgoing,kind,ts,status,body FROM messages"
                     " WHERE contact_id=? AND (?=0 OR ts<?) ORDER BY ts DESC LIMIT ?",
                     -1, &st.p, nullptr);
  sqlite3_bind_int64(st.p, 1, contact_id);
  sqlite3_bind_int64(st.p, 2, before_ts);
  sqlite3_bind_int64(st.p, 3, before_ts);
  sqlite3_bind_int64(st.p, 4, static_cast<sqlite3_int64>(limit));
  std::vector<MessageRow> out;
  while (sqlite3_step(st.p) == SQLITE_ROW) {
    MessageRow m;
    m.id = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 0));
    m.contact_id = contact_id;
    m.outgoing = sqlite3_column_int(st.p, 1) != 0;
    m.kind = static_cast<MsgKind>(sqlite3_column_int(st.p, 2));
    m.ts = sqlite3_column_int64(st.p, 3);
    m.status = static_cast<MsgStatus>(sqlite3_column_int(st.p, 4));
    const auto* blob = static_cast<const std::uint8_t*>(sqlite3_column_blob(st.p, 5));
    crypto::Bytes plain = open_col(crypto::Bytes(blob, blob + sqlite3_column_bytes(st.p, 5)));
    m.body.assign(reinterpret_cast<const char*>(plain.data()), plain.size());
    out.push_back(std::move(m));
  }
  return out;  // newest first
}

void Db::set_message_status(const std::string& id, MsgStatus status) {
  Stmt st;
  sqlite3_prepare_v2(db_, "UPDATE messages SET status=? WHERE id=?", -1, &st.p, nullptr);
  sqlite3_bind_int(st.p, 1, static_cast<int>(status));
  bind_text(st.p, 2, id);
  sqlite3_step(st.p);
}

// ------------------------------------------------------------------ outbox

void Db::outbox_put(const std::string& msg_id, std::int64_t contact_id,
                    const crypto::Bytes& payload_plain) {
  const crypto::Bytes sealed = seal_col(payload_plain.data(), payload_plain.size());
  Stmt st;
  sqlite3_prepare_v2(db_,
                     "INSERT OR REPLACE INTO outbox(msg_id,contact_id,created_at,payload)"
                     " VALUES(?,?,?,?)",
                     -1, &st.p, nullptr);
  bind_text(st.p, 1, msg_id);
  sqlite3_bind_int64(st.p, 2, contact_id);
  sqlite3_bind_int64(st.p, 3, now_ms());
  bind_blob(st.p, 4, sealed.data(), sealed.size());
  if (sqlite3_step(st.p) != SQLITE_DONE) throw std::runtime_error("outbox_put failed");
}

std::vector<OutboxRow> Db::outbox_for(std::int64_t contact_id) {
  Stmt st;
  sqlite3_prepare_v2(db_,
                     "SELECT msg_id,created_at,payload FROM outbox WHERE contact_id=?"
                     " ORDER BY created_at",
                     -1, &st.p, nullptr);
  sqlite3_bind_int64(st.p, 1, contact_id);
  std::vector<OutboxRow> out;
  while (sqlite3_step(st.p) == SQLITE_ROW) {
    OutboxRow r;
    r.msg_id = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 0));
    r.contact_id = contact_id;
    r.created_at = sqlite3_column_int64(st.p, 1);
    const auto* blob = static_cast<const std::uint8_t*>(sqlite3_column_blob(st.p, 2));
    r.payload = open_col(crypto::Bytes(blob, blob + sqlite3_column_bytes(st.p, 2)));
    out.push_back(std::move(r));
  }
  return out;
}

void Db::outbox_del(const std::string& msg_id) {
  Stmt st;
  sqlite3_prepare_v2(db_, "DELETE FROM outbox WHERE msg_id=?", -1, &st.p, nullptr);
  bind_text(st.p, 1, msg_id);
  sqlite3_step(st.p);
}

// ------------------------------------------------------------------ files

void Db::file_put(const FileRow& f) {
  Stmt st;
  sqlite3_prepare_v2(db_,
                     "INSERT OR REPLACE INTO files(id,msg_id,contact_id,outgoing,voice,name,mime,"
                     "size,hash,total_chunks,received_chunks,state,local_path)"
                     " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     -1, &st.p, nullptr);
  bind_text(st.p, 1, f.id);
  bind_text(st.p, 2, f.msg_id);
  sqlite3_bind_int64(st.p, 3, f.contact_id);
  sqlite3_bind_int(st.p, 4, f.outgoing ? 1 : 0);
  sqlite3_bind_int(st.p, 5, f.voice ? 1 : 0);
  bind_text(st.p, 6, f.name);
  bind_text(st.p, 7, f.mime);
  sqlite3_bind_int64(st.p, 8, static_cast<sqlite3_int64>(f.size));
  bind_blob(st.p, 9, f.hash.data(), f.hash.size());
  sqlite3_bind_int(st.p, 10, static_cast<int>(f.total_chunks));
  sqlite3_bind_int(st.p, 11, static_cast<int>(f.received_chunks));
  sqlite3_bind_int(st.p, 12, static_cast<int>(f.state));
  bind_text(st.p, 13, f.local_path);
  if (sqlite3_step(st.p) != SQLITE_DONE) throw std::runtime_error("file_put failed");
}

std::optional<FileRow> Db::file_get(const std::string& id) {
  Stmt st;
  sqlite3_prepare_v2(db_,
                     "SELECT msg_id,contact_id,outgoing,voice,name,mime,size,hash,total_chunks,"
                     "received_chunks,state,local_path FROM files WHERE id=?",
                     -1, &st.p, nullptr);
  bind_text(st.p, 1, id);
  if (sqlite3_step(st.p) != SQLITE_ROW) return std::nullopt;
  FileRow f;
  f.id = id;
  f.msg_id = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 0));
  f.contact_id = sqlite3_column_int64(st.p, 1);
  f.outgoing = sqlite3_column_int(st.p, 2) != 0;
  f.voice = sqlite3_column_int(st.p, 3) != 0;
  f.name = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 4));
  f.mime = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 5));
  f.size = static_cast<std::uint64_t>(sqlite3_column_int64(st.p, 6));
  std::memcpy(f.hash.data(), sqlite3_column_blob(st.p, 7), 32);
  f.total_chunks = static_cast<std::uint32_t>(sqlite3_column_int(st.p, 8));
  f.received_chunks = static_cast<std::uint32_t>(sqlite3_column_int(st.p, 9));
  f.state = static_cast<FileState>(sqlite3_column_int(st.p, 10));
  f.local_path = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 11));
  return f;
}

std::vector<FileRow> Db::files_pending_send(std::int64_t contact_id) {
  Stmt st;
  sqlite3_prepare_v2(db_,
                     "SELECT id,msg_id,outgoing,voice,name,mime,size,hash,total_chunks,"
                     "received_chunks,state,local_path FROM files"
                     " WHERE contact_id=? AND outgoing=1 AND state=0",
                     -1, &st.p, nullptr);
  sqlite3_bind_int64(st.p, 1, contact_id);
  std::vector<FileRow> out;
  while (sqlite3_step(st.p) == SQLITE_ROW) {
    FileRow f;
    // SELECT order: id,msg_id,outgoing,voice,name,mime,size,hash,total_chunks,received_chunks,state,local_path
    f.id = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 0));
    f.msg_id = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 1));
    f.contact_id = contact_id;
    f.outgoing = sqlite3_column_int(st.p, 2) != 0;
    f.voice = sqlite3_column_int(st.p, 3) != 0;
    f.name = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 4));
    f.mime = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 5));
    f.size = static_cast<std::uint64_t>(sqlite3_column_int64(st.p, 6));
    std::memcpy(f.hash.data(), sqlite3_column_blob(st.p, 7), 32);
    f.total_chunks = static_cast<std::uint32_t>(sqlite3_column_int(st.p, 8));
    f.received_chunks = static_cast<std::uint32_t>(sqlite3_column_int(st.p, 9));
    f.state = static_cast<FileState>(sqlite3_column_int(st.p, 10));
    f.local_path = reinterpret_cast<const char*>(sqlite3_column_text(st.p, 11));
    out.push_back(std::move(f));
  }
  return out;
}

void Db::file_set_progress(const std::string& id, std::uint32_t received) {
  Stmt st;
  sqlite3_prepare_v2(db_, "UPDATE files SET received_chunks=? WHERE id=?", -1, &st.p, nullptr);
  sqlite3_bind_int(st.p, 1, static_cast<int>(received));
  bind_text(st.p, 2, id);
  sqlite3_step(st.p);
}

void Db::file_set_state(const std::string& id, FileState state, const std::string& local_path) {
  Stmt st;
  sqlite3_prepare_v2(db_, "UPDATE files SET state=?, local_path=CASE WHEN ?='' THEN local_path ELSE ? END WHERE id=?",
                     -1, &st.p, nullptr);
  sqlite3_bind_int(st.p, 1, static_cast<int>(state));
  bind_text(st.p, 2, local_path);
  bind_text(st.p, 3, local_path);
  bind_text(st.p, 4, id);
  sqlite3_step(st.p);
}

// ------------------------------------------------------------------ chunks

bool Db::chunk_has(const std::string& file_id, std::uint32_t idx) {
  Stmt st;
  sqlite3_prepare_v2(db_, "SELECT 1 FROM chunks WHERE file_id=? AND idx=?", -1, &st.p, nullptr);
  bind_text(st.p, 1, file_id);
  sqlite3_bind_int(st.p, 2, static_cast<int>(idx));
  return sqlite3_step(st.p) == SQLITE_ROW;
}

void Db::chunk_put(const std::string& file_id, std::uint32_t idx, const crypto::Bytes& plain) {
  const crypto::Bytes sealed = seal_col(plain.data(), plain.size());
  Stmt st;
  sqlite3_prepare_v2(db_, "INSERT OR REPLACE INTO chunks(file_id,idx,data) VALUES(?,?,?)", -1,
                     &st.p, nullptr);
  bind_text(st.p, 1, file_id);
  sqlite3_bind_int(st.p, 2, static_cast<int>(idx));
  bind_blob(st.p, 3, sealed.data(), sealed.size());
  if (sqlite3_step(st.p) != SQLITE_DONE) throw std::runtime_error("chunk_put failed");
}

crypto::Bytes Db::chunk_get(const std::string& file_id, std::uint32_t idx) {
  Stmt st;
  sqlite3_prepare_v2(db_, "SELECT data FROM chunks WHERE file_id=? AND idx=?", -1, &st.p, nullptr);
  bind_text(st.p, 1, file_id);
  sqlite3_bind_int(st.p, 2, static_cast<int>(idx));
  if (sqlite3_step(st.p) != SQLITE_ROW) throw std::runtime_error("chunk missing");
  const auto* blob = static_cast<const std::uint8_t*>(sqlite3_column_blob(st.p, 0));
  return open_col(crypto::Bytes(blob, blob + sqlite3_column_bytes(st.p, 0)));
}

void Db::chunk_clear(const std::string& file_id) {
  Stmt st;
  sqlite3_prepare_v2(db_, "DELETE FROM chunks WHERE file_id=?", -1, &st.p, nullptr);
  bind_text(st.p, 1, file_id);
  sqlite3_step(st.p);
}

// ------------------------------------------------------------------ wipe

void Db::wipe() {
  exec("DELETE FROM meta; DELETE FROM contacts; DELETE FROM messages;"
       "DELETE FROM outbox; DELETE FROM files; DELETE FROM chunks;"
       "VACUUM;");
}

} // namespace shopot
