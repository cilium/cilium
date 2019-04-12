#!/bin/bash

CLANG_DIR="clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-14.04"
CLANG_FILE="${CLANG_DIR}.tar.xz"
CLANG_URL="http://releases.llvm.org/3.8.1/$CLANG_FILE"

wget -nv $CLANG_URL
sudo rm -rf /usr/local/clang
sudo mkdir -p /usr/local
sudo tar -C /usr/local -xJf $CLANG_FILE
sudo ln -s /usr/local/$CLANG_DIR /usr/local/clang
rm $CLANG_FILE

NEWPATH="/usr/local/clang/bin"
export PATH="$NEWPATH:$PATH"

go get -u github.com/jteeuwen/go-bindata/...
go get golang.org/x/tools/cmd/cover
go get github.com/mattn/goveralls
curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
