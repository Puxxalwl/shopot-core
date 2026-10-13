// shopot-cli — full-screen chat interface (light-blue theme).
//
// Keys: Tab/Shift+Tab — switch chat · arrows/PgUp/PgDn/wheel — scroll history ·
//       Ctrl+O — attach a file or photo · Esc — cancel · /quit or Ctrl+C — exit.
#include "tui.hpp"
#include "support.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace ftxui;

namespace {

struct Entry {
  enum Kind { Text, FileCard, Sys } kind = Text;
  bool outgoing = false;
  bool err = false;
  std::string time;
  std::string text;
  std::string name;
  std::string status;  // outgoing: "", "queued", "sent", "delivered"
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

struct Model {
  std::mutex mu;
  std::vector<shopot::Contact> contacts;
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

Element tick_element(const Entry& e) {
  if (!e.outgoing || e.status.empty()) return text("");
  if (e.status == "delivered") return text("  ✓✓") | color(Color::SkyBlue1) | bold;
  if (e.status == "sent") return text("  ✓") | color(Color::SkyBlue1);
  return text("  …") | dim;
}

Element text_entry_element(const Entry& e) {
  Element who = e.outgoing ? Element(text("вы") | color(Color::SkyBlue1) | bold)
                           : Element(text(e.name) | color(Color::Cyan1));
  return hbox({
      text(" " + e.time + "  ") | dim,
      who,
      text("  "),
      paragraph(e.text) | (e.outgoing ? color(Color::White) : color(Color::GrayLight)),
      tick_element(e),
  });
}

Element sys_element(const Entry& e) {
  return hbox({
      text("    · ") | dim,
      paragraph(e.text) | (e.err ? color(Color::RedLight) : color(Color::GrayDark)),
  });
}

Element file_entry_element(const Entry& e, const std::map<std::string, FileState>& files) {
  const auto it = files.find(e.file_id);
  const FileState* fs = it == files.end() ? nullptr : &it->second;
  const std::string icon = e.voice ? "🎤" : (e.image ? "🖼" : "📎");
  Elements rows;
  rows.push_back(hbox({
      text(" " + e.time + "  ") | dim,
      e.outgoing ? Element(text("вы") | color(Color::SkyBlue1) | bold)
                 : Element(text(e.name) | color(Color::Cyan1)),
      text("  "),
      text(icon + " "),
      text(e.file_name) | color(Color::SkyBlue1) | bold,
      text("  ·  " + cli_support::human_size(e.file_size)) | dim,
      tick_element(e),
  }));
  if (fs && !fs->finished && fs->total > 0) {
    const double ratio = std::min(1.0, double(fs->done) / double(fs->total));
    std::ostringstream pct;
    pct << int(ratio * 100.0) << "%";
    rows.push_back(hbox({
        text("         "),
        gauge(ratio) | color(Color::SkyBlue1) | size(WIDTH, EQUAL, 28),
        text("  " + pct.str()) | color(Color::SkyBlue1),
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

int run_tui(shopot::Config cfg, const std::string& mnemonic) {
  auto screen = ScreenInteractive::Fullscreen();
  Model M;
  int editor_tab = 0;

  shopot::Events ev;
  const auto post = [&] { screen.PostEvent(Event::Custom); };

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

  shopot::Engine engine(cfg, mnemonic, ev);

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

  const auto do_send_file = [&](const std::string& path, shopot::MsgKind kind) {
    std::int64_t cid;
    {
      std::lock_guard lk(M.mu);
      cid = M.open;
    }
    if (cid == 0) {
      sys_line("нет открытого чата", true);
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
      sys_line(std::string("файл не отправлен: ") + ex.what(), true);
    }
  };

  const auto run_command = [&](const std::string& raw) {
    std::istringstream ss(raw);
    std::string cmd;
    ss >> cmd;
    try {
      if (cmd == "/help" || cmd == "/?") {
        sys_line(
            "Tab — переключить чат · Ctrl+O — файл/фото · /voice <путь> — голосовое\n"
            "/invite — одноразовый код приглашения · /addi <код> [имя] — принять\n"
            "/add <имя> <бандл> · /fp — сверить ключи · /auto — искать всех\n"
            "/rename <имя> · /wipe — стереть всё · /quit — выход");
      } else if (cmd == "/invite") {
        sys_line("код приглашения (одноразовый, передай одному человеку):\n" +
                 engine.make_invite());
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
  in_opt.placeholder = "  написать сообщение…  (Enter — отправить, /help — команды)";
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
      rows.push_back(text("   /add <имя> <бандл>") | dim);
    }
    for (std::size_t i = 0; i < M.contacts.size(); ++i) {
      const auto& c = M.contacts[i];
      const bool sel = int(i) == M.selected;
      const auto un = M.unread.find(c.id);
      Element row = hbox({
          text(c.online ? " ● " : " ○ ") |
              color(c.online ? Color::GreenLight : Color::GrayDark),
          text(trunc_name(c.name, 17)) |
              (sel ? color(Color::SkyBlue1) | bold : color(Color::GrayLight)),
          filler(),
          (un != M.unread.end() && un->second > 0)
              ? Element(text(" " + std::to_string(un->second) + " ") |
                        (bgcolor(Color::SkyBlue1) | color(Color::Black) | bold))
              : Element(text("   ") | dim),
      });
      if (sel) row |= bgcolor(Color::RGB(16, 42, 72));
      rows.push_back(sel ? row | focus : row);
    }
    return vbox(rows) | yframe;
  });

  auto chat_header = Renderer([&] {
    std::lock_guard lk(M.mu);
    if (M.open == 0) return hbox({text("  чат не выбран") | dim});
    for (const auto& c : M.contacts)
      if (c.id == M.open)
        return hbox({
            text("  " + c.name) | bold | color(Color::SkyBlue1),
            text(c.online ? "   ● в сети" : "   ○ не в сети") |
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
          text(" файл ") | bgcolor(Color::SkyBlue1) | color(Color::Black) | bold,
          attach_input->Render() | flex,
          text("  Enter — отправить · Esc — отмена ") | dim,
      });
    }
    if (M.confirm_wipe) {
      return hbox({
          text(" ⚠ введите ДА ") | bgcolor(Color::RedLight) | color(Color::Black) | bold,
          input->Render() | flex,
          text("  сотрёт ВСЮ историю · Esc — отмена ") | dim,
      });
    }
    return hbox({
        text(" ❯ ") | color(Color::SkyBlue1) | bold,
        input->Render() | flex,
    });
  });

  auto header = Renderer([&] {
    std::lock_guard lk(M.mu);
    return hbox({
        text(" shopot ") | bgcolor(Color::SkyBlue1) | color(Color::Black) | bold,
        text("  p2p · e2e · без серверов") | dim,
        filler(),
        text("fp " + M.fp_line + " ") | dim,
    });
  });

  auto status_bar = Renderer([&] {
    std::lock_guard lk(M.mu);
    int online = 0;
    for (const auto& c : M.contacts)
      if (c.online) ++online;
    return hbox({
        text(" Tab чат ") | bgcolor(Color::SkyBlue1) | color(Color::Black),
        text(" ↑↓ история ") | bgcolor(Color::RGB(28, 66, 108)) | color(Color::White),
        text(" Ctrl+O файл ") | bgcolor(Color::RGB(28, 66, 108)) | color(Color::White),
        text(" /help ") | bgcolor(Color::RGB(28, 66, 108)) | color(Color::White),
        filler() | bgcolor(Color::SkyBlue1),
        text(" " + std::to_string(online) + "/" + std::to_string(M.contacts.size()) +
             " онлайн · p2p ")
            | bgcolor(Color::SkyBlue1) | color(Color::Black),
    });
  });

  auto root_renderer = Renderer(editors, [&] {
    return vbox({
        header->Render(),
        hbox({
            contacts_pane->Render() | size(WIDTH, EQUAL, 26),
            separator() | color(Color::RGB(38, 76, 118)),
            vbox({
                chat_header->Render(),
                separator() | color(Color::RGB(38, 76, 118)),
                hist_view->Render() | flex_grow,
                separator() | color(Color::RGB(38, 76, 118)),
                input_area->Render(),
            }) | flex_grow,
        }) | flex_grow,
        status_bar->Render(),
    });
  });

  // ------------------------------------------------------------- keys
  const std::string kCtrlC(1, char(3));
  const std::string kCtrlO(1, char(15));
  auto ui = CatchEvent(root_renderer, [&](const Event& e) {
    if (e.input() == kCtrlC) {
      screen.Exit();
      return true;
    }
    if (e.is_mouse()) {
      Event ev = e;  // mouse() is non-const; work on our copy
      auto m = ev.mouse();
      if (m.button == Mouse::WheelUp) {
        std::lock_guard lk(M.mu);
        if (M.scroll < int(M.hist.size()) - 1) M.scroll += 3;
        post();
        return true;
      }
      if (m.button == Mouse::WheelDown) {
        std::lock_guard lk(M.mu);
        M.scroll = std::max(0, M.scroll - 3);
        post();
        return true;
      }
      return false;
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

  std::atomic<bool> keeper_run{true};
  std::thread keeper = cli_support::run_keeper(engine, keeper_run);

  screen.Loop(ui);
  keeper_run.store(false);
  keeper.join();
  return 0;
}
