// shopot-cli — full-screen chat interface (quiet dark terminal theme).
//
// Selection/copy: the terminal's own text selection works — mouse reporting
// is switched off on purpose, so bundle/invite codes can be copied directly.
#include "tui.hpp"
#include "support.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

using namespace ftxui;

namespace {

struct Entry {
  enum Kind { Text, FileCard, Sys } kind = Text;
  bool outgoing = false;
  bool err = false;
  bool loud = false;
  std::string time;
  std::string text;
  std::string name;
  std::string status;
  std::string msg_id;
  std::string file_id;
  std::string file_name;
  std::uint64_t file_size = 0;
  bool voice = false;
  bool image = false;
};

struct FileState {
  std::uint64_t done = 0;
  std::uint64_t total = 0;
  bool finished = false;
  std::string saved_path;
};

struct CallUi {
  int state = 0;  // 0 idle · 1 out ring · 2 in ring · 3 active
  std::int64_t started_ms = 0;
  std::int64_t peer = 0;
  std::string peer_name;
};
// arecord/aplay child with an explicit pid (pclose would wait forever for
// arecord, which exits only on a signal).
struct Proc {
  FILE* f = nullptr;
  pid_t pid = -1;
  bool live() const { return f != nullptr; }
  static Proc open(const std::string& cmd, const char* mode) {
    Proc p;
    int fds[2];
    if (pipe(fds) != 0) return p;
    const pid_t pid = fork();
    if (pid < 0) { ::close(fds[0]); ::close(fds[1]); return p; }
    if (pid == 0) {
      if (std::strcmp(mode, "r") == 0) ::dup2(fds[1], 1);
      else                            ::dup2(fds[0], 0);
      ::close(fds[0]); ::close(fds[1]);
      execlp("/bin/sh", "sh", "-c", cmd.c_str(), (char*)nullptr);
      _exit(127);
    }
    if (std::strcmp(mode, "r") == 0) { ::close(fds[0]); p.f = fdopen(fds[1], "r"); }
    else                             { ::close(fds[1]); p.f = fdopen(fds[0], "w"); }
    p.pid = pid;
    if (!p.f) { ::kill(pid, SIGKILL); int st; waitpid(pid, &st, 0); p.pid = -1; }
    return p;
  }
  void stop() {
    if (!f) return;
    ::kill(pid, SIGTERM);
    fclose(f);
    f = nullptr;
    int st;
    waitpid(pid, &st, 0);
    pid = -1;
  }
};

struct Model {
  std::mutex mu;
  std::vector<shopot::Contact> contacts;
  CallUi call;
  int selected = 0;
  std::int64_t open = 0;
  std::vector<Entry> hist;
  std::map<std::string, FileState> files;
  std::map<std::int64_t, int> unread;
  std::string input;
  std::string attach_path;
  bool attach = false;
  bool confirm_wipe = false;
  std::string fp_line;
  int scroll = 0;
};

std::int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string trunc_name(const std::string& s, std::size_t max) {
  if (s.size() <= max) return s;
  return s.substr(0, max - 3) + "...";
}

std::string mmss(std::int64_t ms) {
  const int total = int(ms / 1000);
  char buf[16];
  std::snprintf(buf, sizeof buf, "%02d:%02d", total / 60, total % 60);
  return buf;
}

Element tick_element(const Entry& e) {
  if (!e.outgoing || e.status.empty()) return text("");
  if (e.status == "delivered") return text("  ✓✓") | color(Color::GreenLight);
  if (e.status == "sent") return text("  ✓") | color(Color::GrayLight);
  return text("  …") | dim;
}

Element who_element(const Entry& e) {
  return e.outgoing ? Element(text("вы") | bold | color(Color::White))
                    : Element(text(e.name) | bold | color(Color::White));
}

Element text_entry_element(const Entry& e) {
  return hbox({
      text(" " + e.time + "  ") | dim,
      who_element(e),
      text("  "),
      paragraph(e.text) | color(Color::GrayLight),
      tick_element(e),
  });
}

Element sys_element(const Entry& e) {
  if (e.loud)
    return hbox({
        text("    "),
        paragraph(e.text) | bold | color(Color::White),
    });
  return hbox({
      text("    · ") | dim,
      paragraph(e.text) | (e.err ? color(Color::RedLight) : dim),
  });
}

Element file_entry_element(const Entry& e, const std::map<std::string, FileState>& files) {
  const auto it = files.find(e.file_id);
  const FileState* fs = it == files.end() ? nullptr : &it->second;
  const std::string icon = e.voice ? "🎤" : (e.image ? "🖼" : "📎");
  Elements rows;
  rows.push_back(hbox({
      text(" " + e.time + "  ") | dim,
      who_element(e),
      text("  "),
      text(icon + " ") | dim,
      text(e.file_name) | bold | color(Color::White),
      text("  ·  " + cli_support::human_size(e.file_size)) | dim,
      tick_element(e),
  }));
  if (fs && !fs->finished && fs->total > 0) {
    const double ratio = std::min(1.0, double(fs->done) / double(fs->total));
    std::ostringstream pct;
    pct << int(ratio * 100.0) << "%";
    rows.push_back(hbox({
        text("         "),
        gauge(ratio) | color(Color::GrayLight) | size(WIDTH, EQUAL, 28),
        text("  " + pct.str()) | dim,
    }));
  } else if (fs && fs->finished && !e.outgoing && !fs->saved_path.empty()) {
    rows.push_back(hbox({
        text("         ✓ сохранено: ") | color(Color::GreenLight),
        paragraph(fs->saved_path) | color(Color::GreenLight),
    }));
  }
  return vbox(rows);
}

} // namespace

// run_tui itself follows in part 2
int run_tui(shopot::Config cfg, const std::string& mnemonic) {
  auto screen = ScreenInteractive::Fullscreen();
  screen.TrackMouse(false);  // keep the terminal's own selection/copy working
  Model M;
  int editor_tab = 0;

  shopot::Events ev;
  const auto post = [&] { screen.PostEvent(Event::Custom); };
  shopot::Engine* engine_ptr = nullptr;  // set after engine construction below

  // ------------------------------------------------- audio (arecord/aplay)
  Proc rec;
  Proc play;
  std::thread rec_thread;
  const auto audio_stop = [&] {
    if (rec.live()) rec.stop();
    if (rec_thread.joinable()) rec_thread.join();
    if (play.live()) play.stop();
  };
  const auto audio_start = [&](std::int64_t cid) {
    audio_stop();
    rec = Proc::open("arecord -q -f S16_LE -r 16000 -c 1 -t raw 2>/dev/null", "r");
    if (!rec.live()) return false;
    static std::uint8_t buf[640];  // 20 ms of s16le mono 16 kHz
    rec_thread = std::thread([cid, &engine_ref = *engine_ptr, &rec] {
      while (rec.f) {
        const size_t n = fread(buf, 1, sizeof buf, rec.f);
        if (n == 0) break;
        try {
          engine_ref.push_call_audio(cid, buf, n);
        } catch (...) { break; }
      }
    });
    play = Proc::open("aplay -q -f S16_LE -r 16000 -c 1 -t raw 2>/dev/null", "w");
    return true;
  };

  // ------------------------------------------------------------- events
  ev.on_message = [&](const shopot::Message& m) {
    std::lock_guard lk(M.mu);
    if (m.contact_id == M.open) {
      Entry e;
      e.kind = m.kind == shopot::MsgKind::Text ? Entry::Text : Entry::FileCard;
      e.outgoing = m.outgoing;
      e.time = cli_support::hhmm(m.ts);
      e.msg_id = m.id;
      for (const auto& c : M.contacts)
        if (c.id == m.contact_id) e.name = c.name;
      if (e.outgoing) e.name = "вы";
      if (m.kind == shopot::MsgKind::Text) {
        e.text = m.text;
        e.status = "queued";
      } else {
        e.file_id = m.file_id;
        e.file_name = m.file_name;
        e.file_size = m.file_size;
        e.voice = m.kind == shopot::MsgKind::Voice;
        e.image = cli_support::is_image_mime(m.mime);
      }
      M.hist.push_back(std::move(e));
      if (M.scroll != 0) ++M.scroll;
    } else {
      M.unread[m.contact_id]++;
    }
    post();
  };
  ev.on_presence = [&](std::int64_t cid, bool online) {
    std::lock_guard lk(M.mu);
    for (auto& c : M.contacts)
      if (c.id == cid) c.online = online;
    if (cid == M.open) {
      Entry e;
      e.kind = Entry::Sys;
      std::string name = "пир";
      for (const auto& c : M.contacts)
        if (c.id == cid) name = c.name;
      e.text = std::string(online ? "● " : "○ ") + name +
               (online ? " в сети" : " не в сети — отправленное ляжет в очередь");
      M.hist.push_back(std::move(e));
      if (M.scroll != 0) ++M.scroll;
    }
    post();
  };
  ev.on_status = [&](const std::string& id, shopot::MsgStatus st) {
    std::lock_guard lk(M.mu);
    const char* s = st == shopot::MsgStatus::Delivered
                        ? "delivered"
                        : st == shopot::MsgStatus::Sent ? "sent" : "queued";
    for (auto& e : M.hist)
      if (e.msg_id == id) e.status = s;
    post();
  };
  ev.on_file_progress = [&](const shopot::FileProgress& p) {
    std::lock_guard lk(M.mu);
    auto& fs = M.files[p.file_id];
    fs.done = p.done_bytes;
    fs.total = p.total_bytes;
    post();
  };
  ev.on_file_ready = [&](std::int64_t cid, const shopot::Message& m, const std::string& path) {
    std::lock_guard lk(M.mu);
    auto& fs = M.files[m.file_id];
    fs.finished = true;
    fs.saved_path = path;
    if (cid == M.open) {
      Entry e;
      e.kind = Entry::Sys;
      e.text = "файл получен и проверен: " + path;
      M.hist.push_back(std::move(e));
    }
    post();
  };
  ev.on_error = [&](std::int64_t cid, const std::string& err) {
    std::lock_guard lk(M.mu);
    if (cid != 0 && cid != M.open) return;
    Entry e;
    e.kind = Entry::Sys;
    e.err = true;
    e.text = "ошибка: " + err;
    M.hist.push_back(std::move(e));
    if (M.scroll != 0) ++M.scroll;
    post();
  };
  ev.on_contact_added = [&](std::int64_t cid, const std::string& name) {
    {
      std::lock_guard lk(M.mu);
      Entry e;
      e.kind = Entry::Sys;
      e.text = "новый контакт из инвайта: " + name + " (id=" + std::to_string(cid) + ")";
      M.hist.push_back(std::move(e));
    }
    post();
  };

  // call events: UI state + arecord/aplay lifecycle
  ev.on_call_event = [&](const shopot::CallEvent& ce) {
    bool want_audio = false, stop_audio = false;
    std::string loud_err;
    {
      std::lock_guard lk(M.mu);
      switch (ce.state) {
        case shopot::CallState::OutgoingRing: {
          M.call = {};
          M.call.state = 1;
          M.call.started_ms = now_ms();
          M.call.peer = ce.contact_id;
          for (const auto& c : M.contacts)
            if (c.id == ce.contact_id) M.call.peer_name = c.name;
          Entry e;
          e.kind = Entry::Sys;
          e.text = "вызов " + M.call.peer_name + "…  (/hangup — отменить)";
          M.hist.push_back(e);
          break;
        }
        case shopot::CallState::IncomingRing: {
          M.call = {};
          M.call.state = 2;
          M.call.started_ms = now_ms();
          M.call.peer = ce.contact_id;
          for (const auto& c : M.contacts)
            if (c.id == ce.contact_id) M.call.peer_name = c.name;
          Entry e;
          e.kind = Entry::Sys;
          e.loud = true;
          e.text = "ВХОДЯЩИЙ ЗВОНОК: " + M.call.peer_name +
                   "  —  /accept принять · /decline отклонить";
          M.hist.push_back(e);
          break;
        }
        case shopot::CallState::Active:
          if (M.call.state != 3) {
            M.call.state = 3;
            M.call.started_ms = now_ms();
            want_audio = true;
            Entry e;
            e.kind = Entry::Sys;
            e.text = "разговор начат: " + M.call.peer_name + "  (/hangup завершить)";
            M.hist.push_back(e);
          }
          break;
        case shopot::CallState::Ended: {
          if (M.call.state == 0) break;
          const std::string why = ce.reason == "declined" ? "отклонён"
                                  : ce.reason == "timeout" ? "без ответа"
                                  : ce.reason == "local"   ? "завершён"
                                                           : "завершён собеседником";
          M.call.state = 0;
          stop_audio = true;
          Entry e;
          e.kind = Entry::Sys;
          e.text = "звонок " + why;
          M.hist.push_back(e);
          break;
        }
        case shopot::CallState::Idle:
          break;
      }
      if (M.scroll != 0) ++M.scroll;
    }
    if (want_audio && engine_ptr) {
      std::int64_t cid;
      {
        std::lock_guard lk(M.mu);
        cid = M.call.peer;
      }
      if (!audio_start(cid)) loud_err = "нет arecord/aplay (alsa-utils) — звука нет, разговор идёт";
    }
    if (stop_audio) audio_stop();
    if (!loud_err.empty()) {
      std::lock_guard lk(M.mu);
      Entry e;
      e.kind = Entry::Sys;
      e.err = true;
      e.text = loud_err;
      M.hist.push_back(e);
    }
    post();
  };
  ev.on_call_audio = [&](std::int64_t, const std::uint8_t* d, std::size_t n) {
    if (play.f) std::fwrite(d, 1, n, play.f);
  };

  shopot::Engine engine(cfg, mnemonic, ev);
  engine_ptr = &engine;

  // --------------------------------------------------------- model loading
  const auto reload_contacts = [&] {
    std::lock_guard lk(M.mu);
    M.contacts = engine.contacts();
    if (M.selected >= int(M.contacts.size())) M.selected = int(M.contacts.size()) - 1;
    if (M.selected < 0) M.selected = 0;
    M.open = M.contacts.empty() ? 0 : M.contacts[size_t(M.selected)].id;
  };
  reload_contacts();

  const auto load_history = [&] {
    std::int64_t cid;
    std::string name;
    {
      std::lock_guard lk(M.mu);
      cid = M.open;
      for (const auto& c : M.contacts)
        if (c.id == cid) name = c.name;
    }
    std::vector<shopot::Message> msgs;
    if (cid != 0) {
      msgs = engine.history(cid, 200);
      std::reverse(msgs.begin(), msgs.end());
    }
    std::lock_guard lk(M.mu);
    M.hist.clear();
    M.scroll = 0;
    std::string last_day;
    for (const auto& m : msgs) {
      const std::string day = cli_support::day_label(m.ts);
      if (day != last_day) {
        Entry d;
        d.kind = Entry::Sys;
        d.text = "——— " + day + " ———";
        M.hist.push_back(d);
        last_day = day;
      }
      Entry e;
      e.kind = m.kind == shopot::MsgKind::Text ? Entry::Text : Entry::FileCard;
      e.outgoing = m.outgoing;
      e.time = cli_support::hhmm(m.ts);
      e.name = e.outgoing ? "вы" : name;
      e.msg_id = m.id;
      const char* st = m.status == shopot::MsgStatus::Delivered
                           ? "delivered"
                           : m.status == shopot::MsgStatus::Sent ? "sent" : "queued";
      if (m.kind == shopot::MsgKind::Text) {
        e.text = m.text;
        e.status = m.outgoing ? st : "";
      } else {
        e.file_id = m.file_id;
        e.file_name = m.file_name;
        e.file_size = m.file_size;
        e.voice = m.kind == shopot::MsgKind::Voice;
        e.image = cli_support::is_image_mime(m.mime);
        e.status = m.outgoing ? st : "";
      }
      M.hist.push_back(std::move(e));
    }
  };
  if (M.open != 0) load_history();

  // ------------------------------------------------------------- actions
  const auto sys_line = [&](const std::string& s, bool err = false) {
    std::lock_guard lk(M.mu);
    Entry e;
    e.kind = Entry::Sys;
    e.text = s;
    e.err = err;
    M.hist.push_back(std::move(e));
    M.scroll = 0;
    post();
  };

  const auto reload_contacts_ui = [&] {
    reload_contacts();
    load_history();
    post();
  };

  const auto open_selected = [&] {
    {
      std::lock_guard lk(M.mu);
      M.open = M.contacts.empty() ? 0 : M.contacts[size_t(M.selected)].id;
      if (M.open != 0) M.unread[M.open] = 0;
    }
    load_history();
    post();
  };

  const auto do_send_file = [&](const std::string& raw_path, shopot::MsgKind kind) {
    std::int64_t cid;
    {
      std::lock_guard lk(M.mu);
      cid = M.open;
    }
    if (cid == 0) {
      sys_line("нет открытого чата", true);
      return;
    }
    const std::string path = cli_support::expand_path(raw_path);
    if (path.empty() || path[0] != '/') {
      sys_line("укажите полный путь (от /) или начните с ~/ — иначе файл не найти", true);
      return;
    }
    try {
      const std::string mime = cli_support::mime_from_ext(path);
      engine.send_file(cid, path, mime, kind);
      std::lock_guard lk(M.mu);
      Entry e;
      e.kind = Entry::FileCard;
      e.outgoing = true;
      e.time = cli_support::hhmm(now_ms());
      e.file_name = path.substr(path.find_last_of('/') + 1);
      e.image = cli_support::is_image_mime(mime);
      e.voice = kind == shopot::MsgKind::Voice;
      e.status = "queued";
      M.hist.push_back(std::move(e));
      M.scroll = 0;
      post();
    } catch (const std::exception& ex) {
      sys_line("файл не отправлен (" + path + "): " + ex.what(), true);
    }
  };

  const auto run_command = [&](const std::string& raw) {
    std::istringstream ss(raw);
    std::string cmd;
    ss >> cmd;
    try {
      if (cmd == "/help" || cmd == "/?") {
        sys_line(
            "Tab — чат · ↑↓ PgUp/PgDn — история · Ctrl+O — файл/фото · выделение мышью работает\n"
            "/id — ваш код · /invite — код приглашения · /addi <код> [имя] — принять инвайт\n"
            "/add <имя> <код> · /fp — сверить ключи · /auto — искать всех\n"
            "/call — позвонить · /accept /decline — ответить · /hangup — завершить\n"
            "/rename <имя> · /wipe — стереть всё · /quit — выход");
      } else if (cmd == "/id" || cmd == "/bundle") {
        sys_line("ваш код (передайте тем, кто добавляет вас через /add):\n" +
                 engine.my_bundle());
      } else if (cmd == "/invite") {
        sys_line("код приглашения (одноразовый, передай одному человеку):\n" +
                 engine.make_invite());
      } else if (cmd == "/call") {
        std::int64_t cid;
        {
          std::lock_guard lk(M.mu);
          cid = M.open;
        }
        if (cid == 0) {
          sys_line("нет открытого чата", true);
        } else {
          engine.start_call(cid);
        }
      } else if (cmd == "/accept" || cmd == "/decline") {
        std::int64_t cid;
        bool ringing;
        {
          std::lock_guard lk(M.mu);
          cid = M.call.peer;
          ringing = M.call.state == 2;
        }
        if (!ringing) {
          sys_line("нет входящего звонка", true);
        } else {
          engine.answer_call(cid, cmd == "/accept");
        }
      } else if (cmd == "/hangup") {
        std::int64_t cid;
        bool in_call;
        {
          std::lock_guard lk(M.mu);
          cid = M.call.peer;
          in_call = M.call.state != 0;
        }
        if (!in_call) {
          sys_line("звонка нет", true);
        } else {
          engine.end_call(cid);
        }
      } else if (cmd == "/add") {
        std::string name, bundle;
        ss >> name >> bundle;
        const auto id = engine.add_contact(bundle, name);
        sys_line("контакт добавлен: " + name + " (id=" + std::to_string(id) + ")");
        reload_contacts_ui();
      } else if (cmd == "/addi") {
        std::string code, name;
        ss >> code;
        std::getline(ss, name);
        if (!name.empty() && name[0] == ' ') name.erase(0, 1);
        const auto id = engine.accept_invite(code, name);
        sys_line("инвайт принят (id=" + std::to_string(id) + "), соединяюсь…");
        reload_contacts_ui();
        engine.connect_auto(id);
      } else if (cmd == "/rename") {
        std::string name;
        std::getline(ss, name);
        if (!name.empty() && name[0] == ' ') name.erase(0, 1);
        std::int64_t cid;
        {
          std::lock_guard lk(M.mu);
          cid = M.open;
        }
        if (cid == 0 || name.empty()) {
          sys_line("использование: /rename <новое имя>", true);
        } else {
          engine.rename_contact(cid, name);
          reload_contacts_ui();
        }
      } else if (cmd == "/fp") {
        std::string peers;
        {
          std::lock_guard lk(M.mu);
          for (const auto& c : M.contacts)
            if (c.id == M.open) peers = "\nпир:   " + c.fingerprint;
        }
        sys_line("ваш:    " + engine.my_fingerprint() + peers +
                 "\nсверьте голосом или лично — это защита от подмены (MITM)");
      } else if (cmd == "/auto") {
        engine.listen_invites();
        for (const auto& c : engine.contacts())
          if (!c.online) engine.connect_auto(c.id);
        sys_line("ищу: инвайты + все оффлайн-контакты");
      } else if (cmd == "/send" || cmd == "/voice") {
        std::string path;
        ss >> path;
        if (path.empty()) {
          sys_line("использование: " + cmd + " <путь к файлу>", true);
        } else {
          do_send_file(path, cmd == "/voice" ? shopot::MsgKind::Voice : shopot::MsgKind::File);
        }
      } else if (cmd == "/wipe") {
        std::lock_guard lk(M.mu);
        M.confirm_wipe = true;
        M.input.clear();
        post();
      } else if (cmd == "/quit" || cmd == "/exit") {
        screen.Exit();
      } else {
        sys_line("неизвестная команда: " + cmd + "   (/help — список)", true);
      }
    } catch (const std::exception& ex) {
      sys_line(std::string("ошибка: ") + ex.what(), true);
    }
  };

  std::function<void()> submit_fn;  // wired below, used by the input's on_enter

  const auto submit_input = [&] {
    std::string text;
    bool wipe_mode = false;
    {
      std::lock_guard lk(M.mu);
      wipe_mode = M.confirm_wipe;
      text = M.input;
      M.input.clear();
    }
    if (wipe_mode) {
      if (text == "ДА" || text == "да") {
        engine.wipe();
        sys_line("вся локальная история уничтожена. личность — ваши 12 слов.");
        reload_contacts_ui();
      } else {
        sys_line("стирание отменено");
      }
      std::lock_guard lk(M.mu);
      M.confirm_wipe = false;
      post();
      return;
    }
    if (text.empty()) return;
    if (text[0] == '/') {
      run_command(text);
      return;
    }
    std::int64_t cid;
    {
      std::lock_guard lk(M.mu);
      cid = M.open;
    }
    if (cid == 0) {
      sys_line("нет чата: добавьте контакт (/invite или /add)", true);
      return;
    }
    try {
      const std::string id = engine.send_text(cid, text);
      std::lock_guard lk(M.mu);
      Entry e;
      e.kind = Entry::Text;
      e.outgoing = true;
      e.time = cli_support::hhmm(now_ms());
      e.text = text;
      e.name = "вы";
      e.msg_id = id;
      e.status = "queued";
      M.hist.push_back(std::move(e));
      M.scroll = 0;
      post();
    } catch (const std::exception& ex) {
      sys_line(std::string("не отправлено: ") + ex.what(), true);
    }
  };
  submit_fn = submit_input;

  // ---------------------------------------------------------- components
  InputOption in_opt;
  in_opt.content = &M.input;
  in_opt.placeholder = "  сообщение…  (Enter — отправить, /help — команды)";
  in_opt.on_enter = [&] { submit_fn(); };
  auto input = Input(in_opt);

  InputOption att_opt;
  att_opt.content = &M.attach_path;
  att_opt.placeholder = "  путь к файлу или фото…";
  att_opt.on_enter = [&] {
    std::string path;
    {
      std::lock_guard lk(M.mu);
      path = M.attach_path;
      M.attach_path.clear();
      M.attach = false;
      editor_tab = 0;
    }
    if (!path.empty()) do_send_file(path, shopot::MsgKind::File);
    post();
  };
  auto attach_input = Input(att_opt);

  auto editors = Container::Tab({input, attach_input}, &editor_tab);

  auto contacts_pane = Renderer([&] {
    std::lock_guard lk(M.mu);
    Elements rows;
    if (M.contacts.empty()) {
      rows.push_back(text(""));
      rows.push_back(text("   нет контактов") | dim);
      rows.push_back(text("   /invite — код") | dim);
      rows.push_back(text("   приглашения") | dim);
      rows.push_back(text("   /add <имя> <код>") | dim);
    }
    for (std::size_t i = 0; i < M.contacts.size(); ++i) {
      const auto& c = M.contacts[i];
      const bool sel = int(i) == M.selected;
      const auto un = M.unread.find(c.id);
      Element row = hbox({
          text(sel ? " › " : "   ") | (sel ? bold : dim),
          text(c.online ? "● " : "○ ") |
              color(c.online ? Color::GreenLight : Color::GrayDark),
          text(trunc_name(c.name, 16)) |
              (sel ? bold | color(Color::White) : color(Color::GrayLight)),
          filler(),
          (un != M.unread.end() && un->second > 0)
              ? Element(text(std::to_string(un->second) + " ") | bold | color(Color::White))
              : Element(text("  ") | dim),
      });
      rows.push_back(sel ? row | focus : row);
    }
    return vbox(rows) | yframe;
  });

  auto chat_header = Renderer([&] {
    std::lock_guard lk(M.mu);
    if (M.call.state != 0) {
      std::string label = M.call.state == 3 ? " разговор " + mmss(now_ms() - M.call.started_ms)
                          : M.call.state == 1 ? " вызов…"
                                              : " входящий звонок";
      return hbox({
          text("  " + M.call.peer_name) | bold | color(Color::White),
          text(label) | bold | color(Color::GreenLight),
          filler(),
          text("fp " + M.call.peer_name.empty() ? "" : "") | dim,
      });
    }
    if (M.open == 0) return hbox({text("  чат не выбран") | dim});
    for (const auto& c : M.contacts)
      if (c.id == M.open)
        return hbox({
            text("  " + c.name) | bold | color(Color::White),
            text(c.online ? "  ● в сети" : "  ○ не в сети") |
                color(c.online ? Color::GreenLight : Color::GrayDark),
            filler(),
            text("fp " + c.fingerprint.substr(0, 7) + " ") | dim,
        });
    return hbox({text("  ?") | dim});
  });

  auto hist_view = Renderer([&] {
    std::lock_guard lk(M.mu);
    Elements els;
    els.reserve(M.hist.size());
    for (const auto& e : M.hist) {
      els.push_back(e.kind == Entry::Sys    ? sys_element(e)
                    : e.kind == Entry::FileCard ? file_entry_element(e, M.files)
                                            : text_entry_element(e));
    }
    if (els.empty())
      return vbox({
                 text(""),
                 text("   сообщений нет. напишите первым —") | dim,
                 text("   если пир оффлайн, всё уйдёт из очереди при встрече") | dim,
             }) |
             yframe;
    int focus_at = int(M.hist.size()) - 1 - M.scroll;
    focus_at = std::max(0, std::min(focus_at, int(els.size()) - 1));
    els[size_t(focus_at)] = els[size_t(focus_at)] | focus;
    return vbox(std::move(els)) | yframe | vscroll_indicator;
  });

  auto input_area = Renderer([&] {
    std::lock_guard lk(M.mu);
    if (M.attach) {
      return hbox({
          text(" файл › ") | bold | color(Color::White),
          attach_input->Render() | flex,
          text("  Enter — отправить · Esc — отмена ") | dim,
      });
    }
    if (M.confirm_wipe) {
      return hbox({
          text(" ⚠ введите ДА › ") | bold | color(Color::RedLight),
          input->Render() | flex,
          text("  сотрёт ВСЮ историю · Esc — отмена ") | dim,
      });
    }
    return hbox({
        text(" › ") | dim,
        input->Render() | flex,
    });
  });

  auto header = Renderer([&] {
    std::lock_guard lk(M.mu);
    return hbox({
        text(" shopot ") | bold | color(Color::White),
        filler(),
        text("fp " + M.fp_line + " ") | dim,
    });
  });

  auto status_bar = Renderer([&] {
    std::lock_guard lk(M.mu);
    int online = 0;
    for (const auto& c : M.contacts)
      if (c.online) ++online;
    std::string right = std::to_string(online) + "/" +
                        std::to_string(M.contacts.size()) + " онлайн · ";
    if (M.call.state == 3)
      right += " разговор " + mmss(now_ms() - M.call.started_ms) + " · ";
    return hbox({
        text(" Tab чат · ↑↓/PgUp история · Ctrl+O файл · /help ") | dim,
        filler(),
        text(right) | dim,
    });
  });

  auto root_renderer = Renderer(editors, [&] {
    return vbox({
        header->Render(),
        separator() | dim,
        hbox({
            contacts_pane->Render() | size(WIDTH, EQUAL, 26),
            separator() | dim,
            vbox({
                chat_header->Render(),
                separator() | dim,
                hist_view->Render() | flex_grow,
                separator() | dim,
                input_area->Render(),
            }) | flex_grow,
        }) | flex_grow,
        separator() | dim,
        status_bar->Render(),
    });
  });

  // ------------------------------------------------------------- keys
  const std::string kCtrlC(1, char(3));
  const std::string kCtrlO(1, char(15));
  // note: no mouse handling at all — text selection stays native
  auto ui = CatchEvent(root_renderer, [&](const Event& e) {
    if (e.input() == kCtrlC) {
      audio_stop();
      screen.Exit();
      return true;
    }
    if (e == Event::Tab || e == Event::TabReverse) {
      {
        std::lock_guard lk(M.mu);
        if (!M.contacts.empty()) {
          const int n = int(M.contacts.size());
          M.selected = (M.selected + (e == Event::Tab ? 1 : n - 1)) % n;
        }
      }
      open_selected();
      return true;
    }
    if (e == Event::ArrowUp || e == Event::PageUp) {
      std::lock_guard lk(M.mu);
      const int step = e == Event::PageUp ? 10 : 1;
      if (!M.hist.empty() && M.scroll < int(M.hist.size()) - 1)
        M.scroll = std::min(int(M.hist.size()) - 1, M.scroll + step);
      post();
      return true;
    }
    if (e == Event::ArrowDown || e == Event::PageDown) {
      std::lock_guard lk(M.mu);
      M.scroll = std::max(0, M.scroll - (e == Event::PageDown ? 10 : 1));
      post();
      return true;
    }
    if (e == Event::Escape) {
      std::lock_guard lk(M.mu);
      M.attach = false;
      M.confirm_wipe = false;
      M.attach_path.clear();
      editor_tab = 0;
      post();
      return true;
    }
    if (e.input() == kCtrlO) {
      std::lock_guard lk(M.mu);
      if (M.open == 0) return true;
      M.attach = !M.attach;
      editor_tab = M.attach ? 1 : 0;
      M.attach_path.clear();
      post();
      return true;
    }
    return false;
  });

  // 1 s redraw while a call is up (timer in the header)
  std::atomic<bool> tick_run{true};
  std::thread ticker([&] {
    while (tick_run.load()) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      {
        std::lock_guard lk(M.mu);
        if (M.call.state != 3) continue;
      }
      screen.PostEvent(Event::Custom);
    }
  });

  std::atomic<bool> keeper_run{true};
  std::thread keeper = cli_support::run_keeper(engine, keeper_run);

  screen.Loop(ui);
  tick_run.store(false);
  ticker.join();
  keeper_run.store(false);
  keeper.join();
  audio_stop();
  return 0;
}
