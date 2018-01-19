#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"
GOPATH=/go/

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"


"${PROVISIONSRC}"/dns.sh

sudo adduser vagrant docker
retry_function "go get -u github.com/jteeuwen/go-bindata/..."

ln -sf /go/bin/* /usr/local/bin/
"${PROVISIONSRC}"/compile.sh
