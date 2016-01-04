#!/bin/bash

mkdir -p install
cd install

wget -r -np -nd http://www.infradead.org/~tgr/cilium-docker-build/

for pkg in *.deb; do
	dpkg -i $pkg
done

usermod -aG docker vagrant

cd ..
rm -rf $HOME/install
