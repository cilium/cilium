#!/bin/bash

set -e

mkdir -p install
cd install

wget -r -np -nd http://www.infradead.org/~tgr/cilium-docker-build/

for pkg in *.deb; do
	dpkg -i $pkg
done

usermod -aG docker vagrant
echo 'DOCKER_OPTS="--storage-driver=overlay"' >> /etc/default/docker

cd ..
rm -rf $HOME/install
