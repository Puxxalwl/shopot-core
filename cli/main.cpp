// shopot-cli — reference client over shopot-core.
//
//   ./shopot-cli --db alice.db --dl dl-alice
//
// In a real terminal it opens the full-screen chat interface (tui.cpp); under
// pipes/scripts it falls back to the classic line REPL (plain.cpp), and
// --plain forces the REPL anywhere.
//
// First run: choose "new", WRITE DOWN the 12 words — they are the account.
// The mnemonic is also stored in <db>.key (mode 0600) so the CLI can unlock
// itself; delete that file to require the words on every start.
#include "plain.hpp"
#include "support.hpp"
#include "tui.hpp"

#include <iostream>
#include <string>
#include <unistd.h>

int main(int argc, char** argv) {
  std::string db_path = "shopot.db";
  std::string dl_dir = "downloads";
  bool plain = false;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--db" && i + 1 < argc) db_path = argv[++i];
    else if (a == "--dl" && i + 1 < argc) dl_dir = argv[++i];
    else if (a == "--plain") plain = true;
    else if (a == "--help" || a == "-h") {
      std::cout << "usage: shopot-cli [--db PATH] [--dl DIR] [--plain]\n"
                << "  a real terminal opens the full-screen chat UI; pipes get the line REPL\n";
      return 0;
    }
  }

  const std::string key_path = db_path + ".key";
  std::string mnemonic = cli_support::read_keyfile(key_path);
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
    cli_support::write_keyfile(key_path, mnemonic);
  }

  shopot::Config cfg;
  cfg.db_path = db_path;
  cfg.download_dir = dl_dir;

  const bool interactive = isatty(0) && isatty(1) && getenv("SHOPT_PLAIN") == nullptr;
  if (plain || !interactive) return run_plain(cfg, mnemonic);
  return run_tui(cfg, mnemonic);
}
