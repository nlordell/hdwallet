FROM mcr.microsoft.com/vscode/devcontainers/rust:0-1

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
 && apt-get -y install --no-install-recommends wabt binaryen
RUN curl -sL https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sdk_12.0_amd64.deb -o /tmp/wasi-sdk.deb \
 && dpkg -i /tmp/wasi-sdk.deb \
 && rm /tmp/wasi-sdk.deb
RUN rustup update \
 && rustup target add wasm32-wasi \
 && rustup toolchain install nightly --component llvm-tools-preview

ENV CC_wasm32_wasi=/opt/wasi-sdk/bin/clang
