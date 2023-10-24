FROM mcr.microsoft.com/devcontainers/rust:1-1-bookworm

RUN apt-get update &&\
    DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends binaryen &&\
    rustup target add wasm32-wasi &&\
    curl https://wasmtime.dev/install.sh -sSf | bash
