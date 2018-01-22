#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"
GOPATH=/go/

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

sudo adduser vagrant docker

"${PROVISIONSRC}"/dns.sh
"${PROVISIONSRC}"/compile.sh
