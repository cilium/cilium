#!/bin/bash

apt-get update
apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

HOSTNAME=$(curl --silent http://metadata.google.internal/computeMetadata/v1/instance/attributes/hostname -H "Metadata-Flavor: Google")
echo "Setting hostname $HOSTNAME"
hostname $HOSTNAME

echo "Installing docker"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get install -y --no-install-recommends \
	docker-ce \
	docker-ce-cli \
	containerd.io

echo "Adding user $USER to group docker"
usermod -aG docker $USER
