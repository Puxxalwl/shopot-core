# shopot — сборка через Zig (единственная зависимость: сам Zig 0.17)
# C++-клиент (cpp-cli/) собирается системным g++ из вендоренных исходников
# (MessagingApp, Apache-2.0, без правок) — OS-пакеты не требуются.
ZIG ?= zig
CXX ?= g++

.PHONY: build test run cli clean

build:
	cd zig && $(ZIG) build -Doptimize=ReleaseFast

# немодифицированный терминальный клиент MessagingApp: ./build/messagingApp
cli:
	mkdir -p build
	$(CXX) -std=c++17 -I cpp-cli/include/TerminalPlusPlus/src \
		cpp-cli/src/messagingApp.cpp -o build/messagingApp

test:
	cd zig && $(ZIG) build test --summary all

run: build
	cd zig && ./zig-out/bin/shopot-zig chat

# запуск C++-клиента против шлюза (порт печатается при старте chat/serve)
run-cli: cli
	./build/messagingApp 7788 127.0.0.1

clean:
	rm -rf zig/zig-out zig/.zig-cache build
