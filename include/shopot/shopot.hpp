// shopot-core — public API.
//
// shopot is a serverless P2P messaging engine: no accounts on any server, no
// message storage anywhere but the peers' own devices, end-to-end encrypted
// with forward secrecy, history in an encrypted local SQLite database.
//
// This header is the entire API surface. GUI/mobile apps link against the
// engine and implement only presentation and OS integration (notifications,
// audio capture, photo pickers...). Signaling (exchanging the connection
// codes) is deliberately manual: the app shows a code, the user passes it to
// the peer through ANY channel they trust. Nothing ever contacts a server
// run by this project — the only third-party contact is a public STUN server
// used to discover the device's own NAT address (it sees IPs, never data).
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace shopot {

// ------------------------------------------------------------------ types

enum class MsgKind { Text, File, Voice };
enum class MsgStatus { Queued, Sent, Delivered, Received };

struct Contact {
  std::int64_t id = 0;
  std::string name;
  std::string bundle;       // base64url public key bundle (what was pasted to add them)
  std::string fingerprint;  // safety number, compare out-of-band to defeat MITM
  bool online = false;
};

struct Message {
  std::string id;
  std::int64_t contact_id = 0;
  bool outgoing = false;
  MsgKind kind = MsgKind::Text;
  std::int64_t ts = 0;  // unix milliseconds
  MsgStatus status = MsgStatus::Queued;
  std::string text;       // kind == Text
  std::string file_id;    // kind == File | Voice
  std::string file_name;
  std::string mime;
  std::uint64_t file_size = 0;
};

/// Real-time call state (one active call per contact pair).
enum class CallState { Idle, OutgoingRing, IncomingRing, Active, Ended };

struct CallEvent {
  std::int64_t contact_id = 0;
  std::string call_id;
  CallState state = CallState::Idle;
  /// why it ended: "declined", "remote", "local", "timeout", "error" (Idle -> "" )
  std::string reason;
};

struct FileProgress {
  std::string file_id;
  std::int64_t contact_id = 0;
  std::uint64_t done_bytes = 0;
  std::uint64_t total_bytes = 0;
  bool incoming = false;
  bool finished = false;
};

struct Config {
  std::string db_path;       // SQLite file; created if missing
  std::string download_dir;  // where incoming files are assembled
  /// Public STUN server used for NAT traversal. Set to an empty string to
  /// disable STUN entirely (LAN, Tor or static-IP deployments).
  std::string stun_server = "stun:stun.l.google.com:19302";
  /// Rendezvous relays for automatic discovery (MQTT over TLS WebSocket).
  /// Both peers derive the same opaque topic and key from their shared room
  /// hash, so a relay sees only a hash and a sealed blob — it cannot read,
  /// forge or correlate anything beyond "two anonymous IPs attempted a
  /// connection around the same time" (same level as STUN). Empty list
  /// disables automatic discovery; manual code exchange always works.
  std::vector<std::string> relays = {"wss://broker.emqx.io:8084/mqtt",
                                     "wss://test.mosquitto.org:8081"};
};

struct Events {
  /// A fully-decrypted incoming message (already persisted to history).
  std::function<void(const Message&)> on_message;
  /// Presence: peer session established / lost.
  std::function<void(std::int64_t contact_id, bool online)> on_presence;
  /// Delivery state of an outgoing message.
  std::function<void(const std::string& msg_id, MsgStatus)> on_status;
  std::function<void(const FileProgress&)> on_file_progress;
  /// Incoming file assembled, hash-verified and written to download_dir.
  std::function<void(std::int64_t contact_id, const Message&, const std::string& local_path)>
      on_file_ready;
  std::function<void(std::int64_t contact_id, const std::string& error)> on_error;
  /// A pending invite was redeemed: a new contact appeared (name is
  /// provisional, rename at will). Fired on the inviter's side.
  std::function<void(std::int64_t contact_id, const std::string& name)> on_contact_added;
  /// Call state transitions.
  std::function<void(const CallEvent&)> on_call_event;
  /// Decrypted audio from the peer, s16le mono 16 kHz raw PCM. The app feeds
  /// it to the speaker; capture goes back through push_call_audio().
  std::function<void(std::int64_t contact_id, const std::uint8_t* data, std::size_t len)>
      on_call_audio;
};

// ------------------------------------------------------------------ engine

class Engine {
public:
  /// 12-word BIP-39 mnemonic. This IS the account: no email, no phone, no
  /// server. Whoever has the words IS the identity — write them down.
  static std::string generate_mnemonic();
  static bool validate_mnemonic(const std::string& phrase);

  /// Unlock (or create) the engine with a mnemonic. All local state lives in
  /// cfg.db_path, encrypted at rest with a key derived from the mnemonic.
  Engine(Config cfg, const std::string& mnemonic, Events events);
  ~Engine();
  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;

  // identity
  std::string my_bundle() const;       // share this so others can add you
  std::string my_fingerprint() const;  // safety number of our own identity

  // contacts
  std::int64_t add_contact(const std::string& bundle, const std::string& name);
  std::vector<Contact> contacts() const;
  void rename_contact(std::int64_t contact_id, const std::string& name);
  void remove_contact(std::int64_t contact_id);

  // --- signaling (manual, code-based) -------------------------------------
  // Connecting to a contact is a three-step dance, like exchanging a secret
  // handshake through any messenger, QR code, or piece of paper:
  //
  //   A: offer  = engine.make_offer(alice)
  //   B: answer = engine.handle_offer(bob, offer)     // B pastes A's code
  //   A: engine.handle_answer(alice, answer)          // A pastes B's code
  //
  // After this the encrypted session establishes itself and queued messages
  // flow. Codes are single-use and expire with the attempt; generate fresh
  // ones for every connection. The engine is intentionally transport-
  // agnostic — apps that want automatic rendezvous can plug a signaling
  // backend (Nostr relays, BitTorrent trackers, ...) over the same core.
  std::string make_offer(std::int64_t contact_id);
  std::string handle_offer(std::int64_t contact_id, const std::string& offer_code);
  void handle_answer(std::int64_t contact_id, const std::string& answer_code);
  void disconnect(std::int64_t contact_id);

  /// --- signaling (automatic, relay-based) ---------------------------------
  /// Both peers call this; whoever is the deterministic initiator publishes
  /// its offer under the pairwise relay topic, the responder answers, and the
  /// session establishes by itself. No code exchange at all — the only prior
  /// step is having added each other's bundle once. Non-blocking: the search
  /// runs on a worker for up to timeout_ms; outcome arrives through
  /// on_presence / on_error. Requires non-empty Config::relays.
  void connect_auto(std::int64_t contact_id, std::int64_t timeout_ms = 120000);

  /// --- invites (one-way onboarding) ---------------------------------------
  /// Generate a one-time invite code: "shopot://i/<bundle + random secret>".
  /// Whoever holds the code can add THIS side and reach it over the
  /// rendezvous relay — the holder's own bundle arrives sealed on the first
  /// connect, so only ONE string ever changes hands. Codes are capabilities:
  /// treat them like keys, share per-person, regenerate freely.
  std::string make_invite();
  /// Accept an invite code from someone else; returns the new contact id.
  /// The contact starts in "pending invite" state and completes the bond on
  /// the next connect_auto.
  std::int64_t accept_invite(const std::string& code, const std::string& name);
  /// Inviter side: listen on all unused invite topics, redeem any join that
  /// arrives (adding the contact), then connect to it. Non-blocking worker,
  /// outcomes via on_contact_added / on_presence / on_error.
  void listen_invites(std::int64_t timeout_ms = 120000);

  // --- calls ---------------------------------------------------------------
  // One active call per contact. Signaling rides the regular encrypted lane;
  // audio rides a lossy second lane, encrypted under a key derived from the
  // room hash and the call id (fresh nonce per packet). Raw s16le mono 16 kHz
  // PCM in both directions; capture/playback devices are the app's business.
  /// Ring the peer. Throws when there is no established session.
  /// Returns the call id. Outcome arrives via on_call_event.
  std::string start_call(std::int64_t contact_id);
  /// Accept or decline an incoming call (IncomingRing).
  void answer_call(std::int64_t contact_id, bool accept);
  /// Hang up any current call with the contact.
  void end_call(std::int64_t contact_id);
  /// Feed captured audio (s16le mono 16 kHz) to the peer. ~20 ms chunks.
  void push_call_audio(std::int64_t contact_id, const std::uint8_t* data, std::size_t len);
  /// Current call state for a contact.
  CallState call_state(std::int64_t contact_id) const;

  // messaging — safe to call while the peer is offline; payloads wait in the
  // encrypted outbox and are flushed automatically when a session establishes.
  std::string send_text(std::int64_t contact_id, const std::string& text);
  /// kind Voice marks the file as a voice note (apps render it inline).
  std::string send_file(std::int64_t contact_id, const std::string& path,
                        const std::string& mime, MsgKind kind = MsgKind::File);
  /// Newest-first history page. before_ts=0 starts from now.
  std::vector<Message> history(std::int64_t contact_id, std::size_t limit,
                               std::int64_t before_ts = 0) const;

  /// Destroy ALL local state: messages, files, contacts, buffered data.
  /// The mnemonic still recovers the identity, but history is gone forever.
  void wipe();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace shopot
