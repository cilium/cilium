#!/bin/bash

PWD=`pwd`
BUILDDIR=docker-build

sudo rm -rf $BUILDDIR
mkdir -p $BUILDDIR
cd $BUILDDIR

# pull docker repo
git clone git://github.com/docker/docker.git
cd docker

# pull latest libnetwork dependency
rm -rf vendor/src/github.com/docker/libnetwork/
cd vendor/src/github.com/docker
git clone git://github.com/tgraf/libnetwork.git -b ipv6-citizen

cd ../../../..

# compile & install docker
make deb

rsync -rvP --delete bundles/latest/build-deb/ubuntu-trusty/ tgr@casper.infradead.org:public_html/cilium-docker-build
