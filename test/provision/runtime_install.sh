#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision/"
export PATH="/usr/local/go/bin:/home/vagrant/go/bin:/usr/local/clang/bin:/home/vagrant/bin:/home/vagrant/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/clang/bin:/usr/local/go/bin"


$PROVISIONSRC/dns.sh

echo "adding user vagrant to run docker"
sudo adduser vagrant docker
