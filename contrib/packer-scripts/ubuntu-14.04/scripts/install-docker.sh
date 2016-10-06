#!/bin/bash

set -e

apt-get update
apt-get install -y apt-transport-https ca-certificates

apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D

echo 'deb https://apt.dockerproject.org/repo ubuntu-trusty main' > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get purge -y lxc-docker
apt-cache policy docker-engine
apt-get install -y docker-engine

usermod -aG docker vagrant
echo 'DOCKER_OPTS="--storage-driver=overlay --iptables=false"' >> /etc/default/docker

service docker restart

cd ..
rm -rf $HOME/install
