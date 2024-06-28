.POSIX:
.SUFFIXES:

CARGO = cargo
WASMOPT = wasm-opt

.PHONY: all
all: check build

.PHONY: check
check:
	$(CARGO) fmt -- --check
	$(CARGO) clippy --locked --all-targets -- -D warnings
	$(CARGO) test

.PHONY: build
build:
	$(CARGO) build --release
	$(CARGO) build --release --target wasm32-wasi
	$(WASMOPT) target/wasm32-wasi/release/hdwallet.wasm -O4 -o target/hdwallet.wasm --strip-debug --strip-producers
