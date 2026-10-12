// shopot-core — local persistence.
//
// Everything sensitive is sealed with the identity storage key BEFORE it
// touches SQLite: message bodies, outbox payloads, file chunks, meta values.
// The database file alone is useless without the mnemonic.
// Schema and column names are visible; contents are not.
#pragma once

#include "crypto.hpp"
#include "shopot/shopot.hpp"  // public MsgKind / MsgStatus enums

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace shopot {

struct ContactRow {
  std::int64_t id = 0;
  crypto::Arr<32> enc_pk{};
  crypto::Arr<32> sign_pk{};
  std::string name;
  std::int64_t created_at = 0;
};

struct MessageRow {
  std::string id;
  std::int64_t contact_id = 0;
  bool outgoing = false;
  MsgKind kind = MsgKind::Text;
  std::int64_t ts = 0;
  MsgStatus status = MsgStatus::Queued;
  std::string body;  // plaintext in memory; sealed at rest
};

struct OutboxRow {
  std::string msg_id;
  std::int64_t contact_id = 0;
  std::int64_t created_at = 0;
  crypto::Bytes payload;  // envelope JSON plaintext in memory; sealed at rest
};

enum class FileState : int { Sending = 0, Receiving = 1, Done = 2, Failed = 3 };

struct FileRow {
  std::string id;  // 16 raw bytes on the wire; hex string here
  std::string msg_id;
  std::int64_t contact_id = 0;
  bool outgoing = false;
  bool voice = false;
  std::string name;
  std::string mime;
  std::uint64_t size = 0;
  crypto::Arr<32> hash{};  // SHA-256 of the plaintext file
  std::uint32_t total_chunks = 0;
  std::uint32_t received_chunks = 0;
  FileState state = FileState::Receiving;
  std::string local_path;  // outgoing: source; incoming: destination once Done
};

class Db {
public:
  /// Opens (creating if needed) the encrypted-at-rest store.
  Db(const std::string& path, const crypto::Arr<32>& storage_key);
  ~Db();
  Db(const Db&) = delete;
  Db& operator=(const Db&) = delete;

  // meta (values sealed)
  void put_meta(const std::string& key, const crypto::Bytes& plaintext);
  std::optional<crypto::Bytes> get_meta(const std::string& key);

  // contacts
  std::int64_t add_contact(const crypto::Arr<32>& enc_pk, const crypto::Arr<32>& sign_pk,
                           const std::string& name);
  std::vector<ContactRow> contacts();
  std::optional<ContactRow> contact(std::int64_t id);
  void rename_contact(std::int64_t id, const std::string& name);
  void remove_contact(std::int64_t id);

  // messages
  void put_message(const MessageRow& m);  // INSERT OR IGNORE (dedupe by id)
  bool has_message(const std::string& id);
  std::optional<MessageRow> get_message(const std::string& id);
  std::vector<MessageRow> history(std::int64_t contact_id, std::size_t limit,
                                  std::int64_t before_ts = 0);
  void set_message_status(const std::string& id, MsgStatus status);

  // outbox (payloads sealed)
  void outbox_put(const std::string& msg_id, std::int64_t contact_id,
                  const crypto::Bytes& payload_plain);
  std::vector<OutboxRow> outbox_for(std::int64_t contact_id);
  void outbox_del(const std::string& msg_id);

  // files
  void file_put(const FileRow& f);
  std::optional<FileRow> file_get(const std::string& id);
  std::vector<FileRow> files_pending_send(std::int64_t contact_id);
  void file_set_progress(const std::string& id, std::uint32_t received);
  void file_set_state(const std::string& id, FileState state, const std::string& local_path = "");

  // file chunks (sealed individually)
  bool chunk_has(const std::string& file_id, std::uint32_t idx);
  void chunk_put(const std::string& file_id, std::uint32_t idx, const crypto::Bytes& plain);
  crypto::Bytes chunk_get(const std::string& file_id, std::uint32_t idx);
  void chunk_clear(const std::string& file_id);

  void wipe();

private:
  sqlite3* db_ = nullptr;
  crypto::Arr<32> key_{};

  void exec(const char* sql);
  crypto::Bytes seal_col(const std::uint8_t* data, std::size_t len) {
    return crypto::seal(key_, data, len);
  }
  crypto::Bytes open_col(const crypto::Bytes& sealed) { return crypto::open(key_, sealed); }
};

} // namespace shopot
