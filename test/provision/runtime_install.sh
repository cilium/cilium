#!/bin/bash
set -e

HOST=$(hostname)

sudo adduser vagrant docker

export GOPATH=/go/
go get -u github.com/jteeuwen/go-bindata/...
ln -sf /go/bin/* /usr/local/bin/
/tmp/provision/compile.sh

