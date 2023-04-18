#!/usr/bin/env bash

# This script update the dns servers to use google ones.
set -e

sudo systemctl disable systemd-resolved.service
sudo service systemd-resolved stop

echo "updating /etc/resolv.conf"

cat <<EOF > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF
