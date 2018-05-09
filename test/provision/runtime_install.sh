#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

echo "editing journald configuration"
sudo bash -c "echo RateLimitIntervalSec=1s >> /etc/systemd/journald.conf"
sudo bash -c "echo RateLimitBurst=1000 >> /etc/systemd/journald.conf"
echo "restarting systemd-journald"
sudo systemctl restart systemd-journald
echo "getting status of systemd-journald"
sudo service systemd-journald status
echo "done configuring journald"

# Delete this section when the new server is ready
# https://github.com/cilium/cilium/pull/3023/files
export GOPATH="/home/vagrant/go"
sudo -E /usr/local/go/bin/go get -d github.com/lyft/protoc-gen-validate

cd ${GOPATH}/src/github.com/lyft/protoc-gen-validate
sudo git checkout 930a67cf7ba41b9d9436ad7a1be70a5d5ff6e1fc
make build

"${PROVISIONSRC}"/dns.sh
"${PROVISIONSRC}"/compile.sh
