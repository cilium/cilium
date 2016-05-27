#!/bin/bash

set -e

cd $HOME

apt-get -y install curl
curl -L  https://github.com/coreos/etcd/releases/download/v2.2.4/etcd-v2.2.4-linux-amd64.tar.gz -o etcd-v2.2.4-linux-amd64.tar.gz
tar xzvf etcd-v2.2.4-linux-amd64.tar.gz

export PATH=$PATH:/home/vagrant/etcd-v2.2.4-linux-amd64
echo 'export PATH=$PATH:/home/vagrant/etcd-v2.2.4-linux-amd64' >> $HOME/.profile

sudo chmod -R 775  /usr/local/go/pkg/
sudo chgrp vagrant /usr/local/go/pkg/

git clone -b v1.3.0-alpha.4 https://github.com/kubernetes/kubernetes.git
cd kubernetes
#patch -p1 < ../go/src/github.com/noironetworks/cilium-net/examples/kubernetes/kubernetes-v1.3.0-alpha.4.patch
