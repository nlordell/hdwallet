# `hdwallet`

Command line tool for generating and using BIP-0032 hierarchical deterministic
wallets for Ethereum.

## Dependencies

- Rust (`cargo` is used for building)
- Binaryen (`wasm-opt` for optimizing the WebAssembly binary)

## Building and Running

This project can be built with `make`:

```
make
```

Additional help is provided on the commandline:

```
hdwallet --help
```

## WebAssembly

Additionally, `hdwallet` is also released as a WASI WebAssembly application.
This ensures that if malicious code were ever to make its way into the released
binary by sneaking in through dependencies or at distribution time, it would
have very limited impact thanks to the strong security gurantees of sandboxing
Wasm modules.

Running the released Wasm binary requires a Wasm runtime. For example with the
[`wasmtime`](https://github.com/bytecodealliance/wasmtime) runtime:

```
wasmtime hdwallet.wasm -- --help
```
