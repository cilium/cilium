#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision/"

$PROVISIONSRC/dns.sh
sudo adduser vagrant docker

export GOPATH=/go/
go get -u github.com/jteeuwen/go-bindata/...
ln -sf /go/bin/* /usr/local/bin/
$PROVISIONSRC/compile.sh
