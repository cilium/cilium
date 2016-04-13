#!/bin/bash

set -e

cd $HOME

wget --quiet https://storage.googleapis.com/golang/go1.6.linux-amd64.tar.gz
mkdir -p /usr/local
tar -C /usr/local -xzf go1.6.linux-amd64.tar.gz
rm go1.6.linux-amd64.tar.gz

wget --quiet http://llvm.org/releases/3.7.1/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz
mkdir -p /usr/local
tar -C /usr/local -xJf clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz
rm clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz

export GOROOT=/usr/local/go
echo "export GOROOT=$GOROOT" >> /home/vagrant/.profile

export GOPATH=/home/vagrant/go
echo "export GOPATH=$GOPATH" >> /home/vagrant/.profile

NEWPATH="$GOROOT/bin:$GOPATH/bin:/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04/bin"
export PATH="$NEWPATH:$PATH"
echo "export PATH=$NEWPATH:\$PATH" >>  /home/vagrant/.profile

rm -rf /home/vagrant/go
mkdir -p /home/vagrant/go/src

go get github.com/tools/godep
cp /home/vagrant/go/bin/godep /usr/bin
