#!/bin/bash

set -e

apt-get autoremove -y
apt-get clean

echo "cleaning up dhcp leases"
rm /var/lib/dhcp/*

echo "Zeroing device to make space..."
dd if=/dev/zero of=/EMPTY bs=1M || true
rm -f /EMPTY
