ARG VARIANT="buster"
FROM mcr.microsoft.com/vscode/devcontainers/rust:${VARIANT}

RUN apt-get update &&\
    DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends binaryen fzf ripgrep tig &&\
    rustup target add wasm32-wasi &&\
    curl https://wasmtime.dev/install.sh -sSf | bash
