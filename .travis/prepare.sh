#!/bin/bash

wget --quiet http://llvm.org/releases/3.7.1/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz
mkdir -p /usr/local
sudo tar -C /usr/local -xJf clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz
rm clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz

NEWPATH="/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04/bin"
export PATH="$NEWPATH:$PATH"
