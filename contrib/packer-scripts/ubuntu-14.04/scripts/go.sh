#!/bin/bash

set -e

cd $HOME

CLANG_DIR="clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-14.04"
CLANG_FILE="${CLANG_DIR}.tar.xz"
CLANG_URL="http://releases.llvm.org/3.8.1/$CLANG_FILE"
CLANGROOT=/usr/local/clang

wget --quiet https://storage.googleapis.com/golang/go1.7.4.linux-amd64.tar.gz
mkdir -p /usr/local
tar -C /usr/local -xzf go1.7.4.linux-amd64.tar.gz
rm go1.7.4.linux-amd64.tar.gz

wget --quiet $CLANG_URL
mkdir -p /usr/local
tar -C /usr/local -xJf $CLANG_FILE
ln -s /usr/local/$CLANG_DIR $CLANGROOT
rm $CLANG_FILE

export GOROOT=/usr/local/go
echo "export GOROOT=$GOROOT" >> /home/vagrant/.profile

export GOPATH=/home/vagrant/go
echo "export GOPATH=$GOPATH" >> /home/vagrant/.profile

NEWPATH="$GOROOT/bin:$GOPATH/bin:$CLANGROOT/bin"
export PATH="$NEWPATH:$PATH"
echo "export PATH=$NEWPATH:\$PATH" >>  /home/vagrant/.profile

echo PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:$CLANGROOT/bin:${GOROOT}/bin" > /etc/environment

rm -rf /home/vagrant/go
mkdir -p /home/vagrant/go/src

go get github.com/tools/godep
cp /home/vagrant/go/bin/godep /usr/bin
