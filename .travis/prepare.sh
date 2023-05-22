#!/usr/bin/env bash

CLANG_VERSION=10.0.0

function setup_env() {
case `uname -m` in
  'x86_64' )
    CLANG_DIR="clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-18.04"
    ;;
  'aarch64' )
    CLANG_DIR="clang+llvm-$CLANG_VERSION-aarch64-linux-gnu"
    ;;
esac
}

function install_clang() {
  CLANG_FILE="$CLANG_DIR.tar.xz"
  CLANG_FILE_SIG="$CLANG_FILE.sig"

  CLANG_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-$CLANG_VERSION/$CLANG_FILE"
  wget -nv $CLANG_URL
  CLANG_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-$CLANG_VERSION/$CLANG_FILE_SIG"
  wget -nv $CLANG_URL

  wget -nv https://releases.llvm.org/$CLANG_VERSION/hans-gpg-key.asc
  gpg --import hans-gpg-key.asc

  if gpg --verify $CLANG_FILE_SIG $CLANG_FILE
  then
    echo $CLANG_FILE verified successfully
  else
    echo ERROR: Failed to verify $CLANG_FILE
    exit 1
  fi

  sudo rm -rf /usr/local/clang
  sudo mkdir -p /usr/local
  sudo tar -C /usr/local -xJf $CLANG_FILE
  sudo ln -s /usr/local/$CLANG_DIR /usr/local/clang
  rm $CLANG_FILE $CLANG_FILE_SIG hans-gpg-key.asc
}

setup_env
install_clang

export PATH="/usr/local/clang/bin:$PATH"

go install github.com/mattn/goveralls@a36c7ef8f23b2952fa6e39663f52107dfc8ad69d # v0.0.11
go install github.com/mfridman/tparse@a20c511a88b880dc2544d77d8bc2cc66a8dec507 # v0.10.3
