// shopot-cli — reference console client over shopot-core.
//
// This is a demo/QA harness, not the product UI: it exercises the full engine
// (identity, contacts, manual signaling, offline queue, files) in a terminal.
//
//   ./shopot-cli --db alice.db --dl dl-alice
//
// First run: choose "new", WRITE DOWN the 12 words — they are the account.
// The mnemonic is also stored in <db>.key (mode 0600) so the CLI can unlock
// itself; delete that file to require the words on every start.
#include "shopot/shopot.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

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

std::string read_keyfile(const std::string& path) {
  std::ifstream in(path);
  std::string words;
  std::getline(in, words);
  while (!words.empty() && (words.back() == '\n' || words.back() == '\r')) words.pop_back();
  return words;
}

void write_keyfile(const std::string& path, const std::string& words) {
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) throw std::runtime_error(std::string("cannot write key file: ") + strerror(errno));
  const std::string data = words + "\n";
  if (write(fd, data.data(), data.size()) != (ssize_t)data.size())
    throw std::runtime_error("cannot write key file");
  close(fd);
}

void print_help() {
  say(R"(commands:
  bundle                      show your contact code (share it)
  fp                          show your safety number
  contacts                    list contacts (* = online)
  add <name> <bundle>         add a contact
  auto <id>                   automatic connect via public relay (both sides)
  offer <id>                  create a connection code for contact
  answer <id> <code>          accept their code, prints yours to send back
  accept <id> <code>          complete the connection with their answer
  msg <id> <text...>          send a text message (queues if offline)
  send <id> <path> [voice]    send a file / voice note
  hist <id> [n]               show last n messages
  wipe                        destroy all local history
  quit
)");
}

} // namespace

int main(int argc, char** argv) {
  std::string db_path = "shopot.db";
  std::string dl_dir = "downloads";
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--db" && i + 1 < argc) db_path = argv[++i];
    else if (a == "--dl" && i + 1 < argc) dl_dir = argv[++i];
    else if (a == "--help" || a == "-h") {
      std::cout << "usage: shopot-cli [--db PATH] [--dl DIR]\n";
      return 0;
    }
  }

  const std::string key_path = db_path + ".key";
  std::string mnemonic = read_keyfile(key_path);
  if (mnemonic.empty()) {
    std::cout << "no identity found. [n]ew identity or [r]estore from words? ";
    std::string choice;
    std::getline(std::cin, choice);
    if (!choice.empty() && (choice[0] == 'n' || choice[0] == 'N')) {
      mnemonic = shopot::Engine::generate_mnemonic();
      std::cout << "\n*** YOUR 12 WORDS — write them down, they ARE the account ***\n  "
                << mnemonic << "\n\n";
    } else {
      std::cout << "enter the 12 words:\n  ";
      std::getline(std::cin, mnemonic);
      while (!mnemonic.empty() && (mnemonic.back() == '\n' || mnemonic.back() == '\r'))
        mnemonic.pop_back();
    }
    if (!shopot::Engine::validate_mnemonic(mnemonic)) {
      std::cerr << "invalid mnemonic\n";
      return 1;
    }
    write_keyfile(key_path, mnemonic);
  }

  shopot::Config cfg;
  cfg.db_path = db_path;
  cfg.download_dir = dl_dir;

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

  shopot::Engine engine(cfg, mnemonic, ev);
  say("shopot-cli ready. your bundle: " + engine.my_bundle());
  print_help();
  std::cout << "> " << std::flush;

  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream ss(line);
    std::string cmd;
    ss >> cmd;
    try {
      if (cmd == "quit" || cmd == "exit") break;
      if (cmd == "help" || cmd.empty()) {
        print_help();
      } else if (cmd == "bundle") {
        say(engine.my_bundle());
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
        ss >> id;
        engine.connect_auto(id);
        say("searching the peer via relay... (run 'auto' on both sides)");
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
        engine.send_file(id, path, "application/octet-stream",
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
  return 0;
}
