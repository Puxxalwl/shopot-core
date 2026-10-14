# shopot — сборка через Zig (единственная зависимость: сам Zig 0.17)
ZIG ?= zig

.PHONY: build test run clean

build:
	cd zig && $(ZIG) build -Doptimize=ReleaseFast

test:
	cd zig && $(ZIG) build test --summary all

run: build
	cd zig && ./zig-out/bin/shopot-zig chat

clean:
	rm -rf zig/zig-out zig/.zig-cache
