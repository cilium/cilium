#!/bin/bash

# This script update the dns servers to use google ones.
set -e

if systemctl status systemd-resolved; then
    sudo systemctl disable systemd-resolved
fi

echo "updating /etc/resolv.conf"

cat <<EOF > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF
