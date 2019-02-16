#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

"${PROVISIONSRC}"/dns.sh
"${PROVISIONSRC}"/compile.sh

curl -LO https://launchpad.net/~joestringer/+archive/ubuntu/ppa/+files/iproute2_4.20.0-1ubuntu0bjn2_amd64.deb
sudo dpkg -i iproute2*deb
