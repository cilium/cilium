#!/bin/bash

set -e

apt-get update
apt-get -y install libseccomp2 libsystemd-journal0

mkdir -p install
cd install

wget --quiet -r -np -nd http://www.infradead.org/~tgr/cilium-docker-build/

for pkg in *.deb; do
	dpkg -i $pkg
done

usermod -aG docker vagrant
echo 'DOCKER_OPTS="--storage-driver=overlay --iptables=false --ipv6"' >> /etc/default/docker

cd ..
rm -rf $HOME/install
