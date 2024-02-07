#!/usr/bin/env bash

CLANG_VERSION=17.0.6

function setup_env() {
case `uname -m` in
  'x86_64' )
    CLANG_DIR="clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-22.04"
    ;;
  'aarch64' )
    CLANG_DIR="clang+llvm-$CLANG_VERSION-aarch64-linux-gnu"
    ;;
esac
}

function install_clang() {
  CLANG_FILE="$CLANG_DIR.tar.xz"

  CLANG_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-$CLANG_VERSION/$CLANG_FILE"
  wget -nv $CLANG_URL

  sudo rm -rf /usr/local/clang
  sudo mkdir -p /usr/local
  sudo tar -C /usr/local -xJf $CLANG_FILE
  sudo ln -s /usr/local/$CLANG_DIR /usr/local/clang
  rm $CLANG_FILE
}

setup_env
install_clang

export PATH="/usr/local/clang/bin:$PATH"

go install github.com/mfridman/tparse@28967170dce4f9f13de77ec857f7aed4c4294a5f # v0.12.3 (main) with -progress
