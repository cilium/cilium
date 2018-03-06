#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

# Delete this section when the new server is ready
# https://github.com/cilium/cilium/pull/3023/files
export GOPATH="/home/vagrant/go"
sudo -E /usr/local/go/bin/go get -d github.com/lyft/protoc-gen-validate

cd ${GOPATH}/src/github.com/lyft/protoc-gen-validate
sudo git checkout 930a67cf7ba41b9d9436ad7a1be70a5d5ff6e1fc
make build

"${PROVISIONSRC}"/dns.sh
"${PROVISIONSRC}"/compile.sh
