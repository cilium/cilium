#!/bin/bash

set -e

apt-get -y install libseccomp2

mkdir -p install
cd install

wget --quiet -r -np -nd http://www.infradead.org/~tgr/cilium-docker-build/

for pkg in *.deb; do
	dpkg -i $pkg
done

usermod -aG docker vagrant
echo 'DOCKER_OPTS="--storage-driver=overlay"' >> /etc/default/docker

cd ..
rm -rf $HOME/install
