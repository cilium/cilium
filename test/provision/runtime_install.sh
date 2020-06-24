#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

# Can be removed once PR #11528 with the golangci-lint replacement is merged.
go get -u github.com/gordonklaus/ineffassign
cp /root/go/bin/ineffassign /usr/local/bin/

"${PROVISIONSRC}"/dns.sh
"${PROVISIONSRC}"/compile.sh
"${PROVISIONSRC}"/wait-cilium.sh
