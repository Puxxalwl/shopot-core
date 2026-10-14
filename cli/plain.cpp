// shopot-cli — plain line-based REPL (pipes/scripts/e2e; the TTY default is tui.cpp)
#include "plain.hpp"
#include "support.hpp"
#include "shopot/shopot.hpp"

#include <atomic>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

namespace {
std::mutex cout_mu;
void say(const std::string& s) {
  std::lock_guard lk(cout_mu);
  std::cout << "\r\x1b[K" << s << "\n> " << std::flush;
}

std::string status_name(shopot::MsgStatus s) {
  switch (s) {
    case shopot::MsgStatus::Queued: return "queued";
    case shopot::MsgStatus::Sent: return "sent";
    case shopot::MsgStatus::Delivered: return "delivered";
    case shopot::MsgStatus::Received: return "";
  }
  return "";
}

void print_help() {
  say(R"(commands:
  id | bundle                 show your contact code (share it)
  fp                          show your safety number
  contacts                    list contacts (* = online)
  add <name> <bundle>         add a contact
  invite                      one-time invite code (share with one person)
  addi <code> [name]          accept someone's invite
  auto [id]                   connect: with id - that peer, without - redeem
                              invites + connect all offline contacts
  offer <id>                  create a connection code for contact
  answer <id> <code>          accept their code, prints yours to send back
  accept <id> <code>          complete the connection with their answer
  call <id>                   start a call (audio: arecord/aplay, s16le 16k mono)
  accept | decline            answer the incoming call
  hangup                      end the current call
  msg <id> <text...>          send a text message (queues if offline)
  send <id> <path> [voice]    send a file / voice note
  hist <id> [n]               show last n messages
  wipe                        destroy all local history
  quit

tip: run shopot-cli in a real terminal for the full-screen chat interface.
)");
}
} // namespace

int run_plain(shopot::Config cfg, const std::string& mnemonic) {
  shopot::Events ev;
  ev.on_message = [](const shopot::Message& m) {
    if (m.kind == shopot::MsgKind::Text)
      say("[" + std::to_string(m.contact_id) + "] " + m.text);
    else
      say("[" + std::to_string(m.contact_id) + "] incoming " +
          (m.kind == shopot::MsgKind::Voice ? "voice note" : "file") + ": " + m.file_name);
  };
  ev.on_presence = [](std::int64_t cid, bool on) {
    say("[" + std::to_string(cid) + "] " + (on ? "ONLINE" : "offline"));
  };
  ev.on_status = [](const std::string& id, shopot::MsgStatus st) {
    if (st == shopot::MsgStatus::Delivered) say("  (delivered " + id.substr(0, 8) + ")");
  };
  ev.on_file_ready = [](std::int64_t cid, const shopot::Message&, const std::string& path) {
    say("[" + std::to_string(cid) + "] file ready: " + path);
  };
  ev.on_error = [](std::int64_t cid, const std::string& e) {
    say("[" + std::to_string(cid) + "] error: " + e);
  };
  ev.on_contact_added = [](std::int64_t cid, const std::string& name) {
    say("new contact from invite: id=" + std::to_string(cid) + " (" + name + ")" +
        "  - connect with: auto " + std::to_string(cid));
  };
  ev.on_call_event = [](const shopot::CallEvent& ce) {
    std::string st;
    switch (ce.state) {
      case shopot::CallState::OutgoingRing: st = "calling... (hangup to cancel)"; break;
      case shopot::CallState::IncomingRing: st = "INCOMING CALL - type: accept | decline"; break;
      case shopot::CallState::Active:       st = "call active (hangup to end)"; break;
      case shopot::CallState::Ended:        st = "call ended (" + ce.reason + ")"; break;
      case shopot::CallState::Idle:         break;
    }
    if (!st.empty()) say("[" + std::to_string(ce.contact_id) + "] " + st);
  };

  shopot::Engine engine(cfg, mnemonic, ev);
  say("shopot-cli ready. your bundle: " + engine.my_bundle());
  print_help();
  std::cout << "> " << std::flush;

  std::atomic<bool> keeper_run{true};
  std::thread keeper = cli_support::run_keeper(engine, keeper_run);

  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream ss(line);
    std::string cmd;
    ss >> cmd;
    try {
      if (cmd == "quit" || cmd == "exit") break;
      if (cmd == "help" || cmd.empty()) {
        print_help();
      } else if (cmd == "bundle" || cmd == "id") {
        say(engine.my_bundle());
      } else if (cmd == "call") {
        std::int64_t cid;
        ss >> cid;
        engine.start_call(cid);
      } else if (cmd == "accept" || cmd == "decline") {
        // incoming call goes to the open contact: plain mode has no "open",
        // so pick the single ringing one via call_state scan
        for (const auto& c : engine.contacts()) {
          if (engine.call_state(c.id) == shopot::CallState::IncomingRing) {
            engine.answer_call(c.id, cmd == "accept");
            break;
          }
        }
      } else if (cmd == "hangup") {
        for (const auto& c : engine.contacts()) {
          const auto st = engine.call_state(c.id);
          if (st == shopot::CallState::Active || st == shopot::CallState::OutgoingRing) {
            engine.end_call(c.id);
            break;
          }
        }
      } else if (cmd == "fp") {
        say(engine.my_fingerprint());
      } else if (cmd == "contacts") {
        for (const auto& c : engine.contacts())
          say(std::string(c.online ? "* " : "  ") + "[" + std::to_string(c.id) + "] " + c.name +
              "\n    fp: " + c.fingerprint);
      } else if (cmd == "add") {
        std::string name, bundle;
        ss >> name >> bundle;
        const auto id = engine.add_contact(bundle, name);
        say("added contact id=" + std::to_string(id));
      } else if (cmd == "invite") {
        say("one-time invite code (share with one person):\n" + engine.make_invite());
      } else if (cmd == "addi") {
        std::string code, name;
        ss >> code;
        std::getline(ss, name);
        if (!name.empty() && name[0] == ' ') name.erase(0, 1);
        const auto id = engine.accept_invite(code, name);
        say("added pending invite as contact id=" + std::to_string(id) +
            "  - connect with: auto " + std::to_string(id));
      } else if (cmd == "offer") {
        std::int64_t id;
        ss >> id;
        say("send this code to the peer:\n" + engine.make_offer(id));
      } else if (cmd == "answer") {
        std::int64_t id;
        std::string code;
        ss >> id >> code;
        say("send this answer back:\n" + engine.handle_offer(id, code));
      } else if (cmd == "accept") {
        std::int64_t id;
        std::string code;
        ss >> id >> code;
        engine.handle_answer(id, code);
        say("answer applied, connecting...");
      } else if (cmd == "auto") {
        std::int64_t id;
        if (ss >> id) {
          engine.connect_auto(id);
          say("searching the peer via relay... (run 'auto' on both sides)");
        } else {
          engine.listen_invites();
          for (const auto& c : engine.contacts())
            if (!c.online) engine.connect_auto(c.id);
          say("searching: pending invites + all offline contacts");
        }
      } else if (cmd == "msg") {
        std::int64_t id;
        ss >> id;
        std::string text;
        std::getline(ss, text);
        if (!text.empty() && text[0] == ' ') text.erase(0, 1);
        engine.send_text(id, text);
        say("  (queued)");
      } else if (cmd == "send") {
        std::int64_t id;
        std::string path, voice;
        ss >> id >> path >> voice;
        engine.send_file(id, path, cli_support::mime_from_ext(path),
                         voice == "voice" ? shopot::MsgKind::Voice : shopot::MsgKind::File);
        say("  (file queued)");
      } else if (cmd == "hist") {
        std::int64_t id;
        std::size_t n = 20;
        ss >> id >> n;
        for (const auto& m : engine.history(id, n)) {
          std::string st = m.outgoing ? status_name(m.status) : "";
          if (!st.empty()) st = " [" + st + "]";
          say((m.outgoing ? ">> " : "<< ") +
              (m.kind == shopot::MsgKind::Text
                   ? m.text
                   : ("[" + std::string(m.kind == shopot::MsgKind::Voice ? "voice" : "file") +
                      ": " + m.file_name + "]")) +
              st);
        }
      } else if (cmd == "wipe") {
        engine.wipe();
        say("all local history destroyed. identity = your 12 words.");
      } else {
        say("unknown command: " + cmd);
      }
    } catch (const std::exception& e) {
      say(std::string("error: ") + e.what());
    }
    std::cout << "> " << std::flush;
  }
  keeper_run.store(false);
  keeper.join();
  return 0;
}
