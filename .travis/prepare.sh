#!/bin/bash

set -x

sudo apt-get -y purge clang

CLANG_DIR="clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-14.04"
CLANG_FILE="${CLANG_DIR}.tar.xz"
CLANG_URL="http://llvm.org/releases/3.8.1/$CLANG_FILE"

wget --quiet $CLANG_URL
sudo mkdir -p /usr/local
sudo tar -C /usr/local -xJf $CLANG_FILE
sudo ln -s /usr/local/$CLANG_DIR /usr/local/clang
rm $CLANG_FILE

NEWPATH="/usr/local/clang/bin"
export PATH="$NEWPATH:$PATH"
