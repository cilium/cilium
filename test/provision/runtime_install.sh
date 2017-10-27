#!/bin/bash
set -e

HOST=$(hostname)
export GOPATH=/go/
go get -u github.com/jteeuwen/go-bindata/...
ln -sf /go/bin/* /usr/local/bin/
/tmp/provision/compile.sh
