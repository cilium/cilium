#!/bin/bash

# This script update the dns servers to use google ones.
set -e

cat <<EOF > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

