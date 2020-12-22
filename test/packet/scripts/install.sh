#!/bin/bash

set -e

# Ensure no prompts from apt & co.
export DEBIAN_FRONTEND=noninteractive

GOLANG_VERSION="1.15.6"
VAGRANT_VERSION="2.2.4"
PACKER_VERSION="1.3.5"
VIRTUALBOX_VERSION="6.0"

#repositories

echo "deb http://download.virtualbox.org/virtualbox/debian bionic contrib" > /etc/apt/sources.list.d/virtualbox.list

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo apt-key fingerprint 0EBFCD88
wget -q http://download.virtualbox.org/virtualbox/debian/oracle_vbox_2016.asc -O- | sudo apt-key add -
wget -q http://download.virtualbox.org/virtualbox/debian/oracle_vbox.asc -O- | sudo apt-key add -
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"

sudo --preserve-env=DEBIAN_FRONTEND apt-get update
sudo --preserve-env=DEBIAN_FRONTEND apt-get install -y \
    curl jq apt-transport-https htop bmon zip \
    linux-tools-common linux-tools-generic \
    ca-certificates software-properties-common \
    git openjdk-8-jdk gcc make perl unzip awscli \
    linux-headers-`uname -r` \
    virtualbox-${VIRTUALBOX_VERSION} docker-ce

cd /tmp/
wget https://releases.hashicorp.com/vagrant/${VAGRANT_VERSION}/vagrant_${VAGRANT_VERSION}_x86_64.deb
dpkg -i vagrant_*.deb

# this block will attempt to preload required vagrant boxes from the vagrant cache server
# (it's configuration is in vagrant-cache directory in root of this repo).
# vagrant cache server is a separate packet box which vagrant-cache.ci.cilium.io points to
cp /provision/add_vagrant_box.sh /usr/local/bin/
chmod 755 /usr/local/bin/add_vagrant_box.sh

curl -s https://raw.githubusercontent.com/cilium/cilium/master/vagrant_box_defaults.rb > defaults.rb
/usr/local/bin/add_vagrant_box.sh defaults.rb

wget https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_amd64.zip
unzip packer_${PACKER_VERSION}_linux_amd64.zip
mv packer /usr/local/bin/

# Kernel parameters
export CPU=$(($(nproc)-1))
for i in $(seq 0 $CPU);
do
   echo performance > /sys/devices/system/cpu/cpu$i/cpufreq/scaling_governor
done

#Install Golang
cd /tmp/
sudo curl -Sslk -o go.tar.gz "https://storage.googleapis.com/golang/go${GOLANG_VERSION}.linux-amd64.tar.gz"
sudo tar -C /usr/local -xzf go.tar.gz
sudo rm go.tar.gz
sudo ln -s /usr/local/go/bin/* /usr/local/bin/
go version
sudo mkdir /go/
export GOPATH=/go/
go get -u github.com/google/gops
go get -u github.com/onsi/ginkgo/ginkgo
go get -u github.com/onsi/gomega/...
sudo ln -sf /go/bin/* /usr/local/bin/

echo 'cd /root/go/src/github.com/cilium/cilium' >> /root/.bashrc
