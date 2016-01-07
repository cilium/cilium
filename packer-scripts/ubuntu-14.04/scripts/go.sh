#!/bin/bash

cd $HOME

wget --quiet https://storage.googleapis.com/golang/go1.5.2.linux-amd64.tar.gz
mkdir -p /usr/local
tar -C /usr/local -xzf go1.5.2.linux-amd64.tar.gz
rm go1.5.2.linux-amd64.tar.gz

export GOROOT=/usr/local/go
echo 'export GOROOT=/usr/local/go' >> $HOME/.bashrc

echo 'export GOPATH=$HOME/go' >> $HOME/.bashrc
export GOPATH=$HOME/go

export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
echo 'export PATH=$GOROOT/bin:$GOPATH/bin:$PATH' >> $HOME/.bashrc

rm -rf /home/vagrant/go
mkdir -p /home/vagrant/go/src

go get github.com/tools/godep
