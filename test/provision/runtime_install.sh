#!/bin/bash
set -e

cat <<EOF > /etc/apt/sources.list
deb http://old-releases.ubuntu.com/ubuntu/ zesty main restricted
deb http://old-releases.ubuntu.com/ubuntu/ zesty-updates main restricted
deb http://old-releases.ubuntu.com/ubuntu/ zesty universe
deb http://old-releases.ubuntu.com/ubuntu/ zesty-updates universe
deb http://old-releases.ubuntu.com/ubuntu/ zesty multiverse
deb http://old-releases.ubuntu.com/ubuntu/ zesty-updates multiverse
deb http://old-releases.ubuntu.com/ubuntu/ zesty-backports main restricted universe multiverse
deb [arch=amd64] https://download.docker.com/linux/ubuntu zesty stable
EOF
sudo apt-get update

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
