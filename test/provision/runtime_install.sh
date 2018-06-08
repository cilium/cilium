#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

echo "editing journald configuration"
sudo bash -c "sed -i 's/RateLimitBurst=1000/RateLimitBurst=10000/' /etc/systemd/journald.conf"
echo "restarting systemd-journald"
sudo systemctl restart systemd-journald
echo "getting status of systemd-journald"
sudo service systemd-journald status
echo "done configuring journald"

"${PROVISIONSRC}"/dns.sh
"${PROVISIONSRC}"/compile.sh
