#ifndef TERMINAL_HPP
#define TERMINAL_HPP

/*
         _____                   _             _
        |_   _|__ _ __ _ __ ___ (_)_ __   __ _| |  _     _
          | |/ _ \ '__| '_ ` _ \| | '_ \ / _` | |_| |_ _| |_
          | |  __/ |  | | | | | | | | | | (_| | |_   _|_   _|
          |_|\___|_|  |_| |_| |_|_|_| |_|\__,_|_| |_|   |_|

        Author: BahaaMohamed98
 */

#include <cstdlib>
#include <functional>
#include <iostream>
#include <thread>

#ifdef _WIN32

#include <conio.h>
#include <windows.h>

#else

#include <cstdio>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>

#endif

// Enum for terminal text colors
enum class Color {
    Black = 30,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    Reset = 0, // Resets to the normal color
};

struct Rgb {
    int r;
    int g;
    int b;

	Rgb(const int r, const int g, const int b): r(r), g(g), b(b) {}
};

// Enum for text styles
enum class Style {
    Normal,
    Bold,
    Dim,
    Italic,
    Underline,
    Blink,
    Reverse,
    Hidden,
    Strike,
};

// Enum for keyboard buttons' keyCodes
enum keyCode {
#ifdef _WIN32
    Backspace = 8,
    Enter     = 13,
#else
    Backspace = 127,
    Enter     = 10,
#endif
    Esc   = 27,
    Tab   = 9,
    Space = 32,

    // arrow keys
#ifdef _WIN32
    ArrowUp    = 72,
    ArrowDown  = 80,
    ArrowRight = 77,
    ArrowLeft  = 75,
#else
    ArrowUp = 65,
    ArrowDown,
    ArrowRight,
    ArrowLeft,
#endif
};

// Options for clearScreen()
// "All" for a complete clear including history
// "Purge" for clearing the visible screen while preserving history
// "Line" for clearing just the current line
enum class ClearType {
    All,   // clear all plus history
    Purge, // clear the screen leaving history
    Line,  // clear the current line
};

class Terminal {
    std::string textColor;       // Holds the current text color
    std::string backgroundColor; // Holds the current background color
    Style textStyle;

    struct TerminalSize {
        int width;
        int height;

        bool operator!=(const TerminalSize& other) const {
            return width != other.width or height != other.height;
        }
    };

    TerminalSize dimensions;
    std::vector<std::thread> threads;

    // Converts a number into an ANSI escape code
    static std::string toAnsi(const int& code) {
        return "\033[" + std::to_string(code) + "m";
    }

    // Converts a Color into an ANSI escape code for the background color
    static std::string backgroundColorToAnsi(const Color& color) {
        if (color == Color::Reset)
            return toAnsi(static_cast<int>(Color::Reset));
        return toAnsi(static_cast<int>(color) + 10);
    }

    // converts an RGB color into an ANSI escape code
    static std::string RgbToAnsi(const Rgb& color_, const bool isBackground) {
        return "\033[" +
               std::string(isBackground ? "48" : "38") + ";2;" +
               std::to_string(color_.r) + ";" + std::to_string(color_.g) + ";" + std::to_string(color_.b) + "m";
    }

public:
    // Reads a single character from the terminal's unbuffered input without any processing.
    // On Windows, uses getch() from <conio.h>.
    // On Unix-like systems, it disables canonical mode and echoing temporarily to capture the input.
    // This function is low-level; only use it if you plan to handle input processing manually.
    static char getRawChar() {
#ifdef _WIN32
        return (char)getch();
#else
        termios oldattr{}, newattr{};
        tcgetattr(STDIN_FILENO, &oldattr); // Get current terminal attributes
        newattr = oldattr;
        newattr.c_lflag &= ~(ICANON | ECHO);        // Disable canonical mode and echoing
        tcsetattr(STDIN_FILENO, TCSANOW, &newattr); // Apply new attributes immediately
        const int ch = getchar();                   // Read a single character
        tcsetattr(STDIN_FILENO, TCSANOW, &oldattr); // Restore original attributes
        return static_cast<char>(ch);
#endif
    }

    explicit Terminal(const Color& textColor = Color::Reset, const Color& backgroundColor = Color::Reset)
        : textColor(toAnsi(static_cast<int>(textColor))),
          backgroundColor(backgroundColorToAnsi(backgroundColor)),
          textStyle(Style::Normal), dimensions(size()) {}

    // Destructor ensures that all spawned threads are joined before the object is destroyed
    // to prevent potential crashes from detached threads running after the object is deleted
    ~Terminal() {
        awaitCompletion();
    }

    // Waits for all non-blocking tasks to finish before continuing
    // Call this after starting tasks with nonBlock()
    Terminal& awaitCompletion() {
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        threads.clear(); // Clear the threads vector after joining
        return *this;
    }

    // returns terminal size struct of (width, height)
    static TerminalSize size() {
        TerminalSize size{0, 0};

#ifdef _WIN32
        CONSOLE_SCREEN_BUFFER_INFO screenBufferInfo;
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &screenBufferInfo)) {
            size.width = screenBufferInfo.srWindow.Right - screenBufferInfo.srWindow.Left + 1;
            size.height = screenBufferInfo.srWindow.Bottom - screenBufferInfo.srWindow.Top + 1;
        }
#else
        winsize w{};
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
            size.height = w.ws_row;
            size.width = w.ws_col;
        }
#endif

        return size;
    }

    // returns true if the terminal was resized
    // should be called from within a loop
    [[nodiscard]] bool isResized() {
        const auto newDimensions = size();

        const bool resized = newDimensions != dimensions;
        dimensions = newDimensions;

        return resized;
    }

    // assigns the new width and height to the given parameters by reference
    [[nodiscard]] bool isResized(int& nWidth, int& nHeight) {
        const auto newDimensions = size();
        nWidth = newDimensions.width, nHeight = newDimensions.height;

        const bool resized = newDimensions != dimensions;
        dimensions = newDimensions;

        return resized;
    }

    // returns true if the terminal was resized
    // should be called using nonBlock as it blocks the thread
    // should be called from within a loop
    [[nodiscard]] static bool keyPressed() {
#ifdef _WIN32
        return _kbhit();  // Windows
#else
        termios oldt{}, newt{};
        int bytesAvailable = 0;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        ioctl(STDIN_FILENO, FIONREAD, &bytesAvailable);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return bytesAvailable > 0; // Linux/macOS
#endif
    }

    // Clears the terminal screen
    static void clearScreen(const ClearType& cleartype = ClearType::All) {
        switch (cleartype) {
            case ClearType::All:
                std::cout << "\033[2J\033[H" << std::flush;
                break;
            case ClearType::Purge:
                std::cout << "\033[2J" << std::flush;
                break;
            case ClearType::Line:
                std::cout << "\33[2K\r" << std::flush;
                break;
        }
    }

    // Sleeps for specified number of milliseconds
    static void sleep(const int& milliseconds) {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }

    // Runs a given lambda function on a separate thread
    Terminal& nonBlock(const std::function<void()>& task, const bool runInBackground = false) {
        if (runInBackground) { // Launches the task in a background thread that runs independently of this object
            std::thread(task).detach(); // detaching the thread
        } else {
            // Adds a new thread to the vector of threads for the task to be executed asynchronously
            // This ensures that the thread can be joined later when the Terminal object is destroyed
            threads.emplace_back(task);
        }
        return *this;
    }

    // Moves the cursor to the specified (x, y) position in the terminal
    // starting from (1, 1) in the top left corner of the terminal
    static void moveTo(const int& x, const int& y) {
        std::cout << "\033[" << y << ";" << x << "H";
    }

    // Prints multiple arguments to the terminal
    template<class T>
    Terminal& print(const T& arg) {
        std::cout << backgroundColor;

        if (textStyle != Style::Normal)
            std::cout << toAnsi(static_cast<int>(textStyle));

        if (textColor != "\033[0m") // if color is not reset, then set it as it will affect the background color
            std::cout << textColor;

        std::cout << arg
                << toAnsi(static_cast<int>(Color::Reset)); // reset colors again

        return *this;
    }

    template<typename T, typename... Args>
    Terminal& print(const T& arg, const Args&... args) {
        print(arg);
        print(args...);
        return *this;
    }

    Terminal& println() {
        print("\n");
        return *this;
    }

    // Prints multiple arguments followed by a newline
    template<typename... Args>
    Terminal& println(const Args&... args) {
        print(args...);
        print("\n");
        return *this;
    }

    // Flushes the output stream
    static void flush() {
        std::cout.flush();
    }

    //Hides the cursor
    static void hideCursor() {
        std::cout << "\033[?25l";
    }

    // Shows the cursor
    static void showCursor() {
        std::cout << "\033[?25h";
    }

    // enables the alternate screen buffer
    // the main screen buffer is saved and restored when switching back
    static void enableAlternateScreen() {
        std::cout << "\033[?1049h" << std::flush;
    }

    // disables the alternate screen buffer
    // switches back to the main screen
    static void disableAlternateScreen() {
        std::cout << "\033[?1049l" << std::flush;
    }

    // Sets the current text color
    Terminal& setTextColor(const Color& color) {
        this->textColor = toAnsi(static_cast<int>(color));
        return *this;
    }

    // takes a number between 0 and 255 and sets it as text color
    Terminal& setTextColor(const int& color) {
        this->textColor = "\033[38;5;" + std::to_string(color) + "m";
        return *this;
    }

    // Sets the text color to a given Rgb value
    Terminal& setTextColor(const Rgb& color) {
        this->textColor = RgbToAnsi(color, false);
        return *this;
    }

    Terminal& setBackgroundColor(const Color& color) {
        this->backgroundColor = backgroundColorToAnsi(color);
        return *this;
    }

    // takes a number between 0 and 255 and sets it as background color
    Terminal& setBackgroundColor(const int& color) {
        this->backgroundColor = "\033[48;5;" + std::to_string(color) + "m";
        return *this;
    }

    // Sets the background color to a given Rgb value
    Terminal& setBackgroundColor(const Rgb& color) {
        this->backgroundColor = RgbToAnsi(color, true);
        return *this;
    }

    // resets text and background colors
    Terminal& resetColors() {
        textColor.clear();
        backgroundColor.clear();
        return *this;
    }

    // sets the text style
    Terminal& setStyle(const Style& style) {
        this->textStyle = style;
        return *this;
    }

    // sets the terminal title
    // may print unwanted text on some terminals
    static void setTitle(const std::string& title) {
        std::cout << "\033]2;" << title << "\007";
    }

    // Reads a single character with arrow key support for Unix-like systems.
    //  Captures arrow keys by recognizing ESC sequences and interprets them accordingly.
    //  Uses getRawChar() internally to handle cross-platform compatibility.
    static char getChar() {
#ifdef _WIN32
        return  getRawChar();
#else
        char input = getRawChar();
        if (input == 27 and keyPressed())
            input = getRawChar();
        if (input == '[' and keyPressed())
            input = getRawChar();
        return input;
#endif
    }

    // gets a string from stdin
    static std::string getString(const std::string& prompt = "") {
        std::cout << prompt;
        std::string str;

        std::cin >> str;
        std::cin.ignore();
        return str;
    }

    // gets a full line from stdin
    static std::string getLine(const std::string& prompt = "") {
        std::cout << prompt;
        std::string line;

        getline(std::cin, line, '\n');
        return line;
    }
};

#endif //TERMINAL_HPP
