#!/bin/bash

set -e

# Set up dns
cat <<EOF > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
options timeout:2 attempts:1 rotate
EOF

# Set up sudo
echo "%vagrant ALL=NOPASSWD:ALL" > /etc/sudoers.d/vagrant
chmod 0440 /etc/sudoers.d/vagrant

# Setup sudo to allow no-password sudo for "sudo"
usermod -a -G sudo vagrant

apt-get install openssh-server -y

# Installing vagrant keys
mkdir -p ~/.ssh
chmod 700 ~/.ssh
cd ~/.ssh

wget --no-check-certificate 'https://raw.github.com/mitchellh/vagrant/master/keys/vagrant.pub' -O authorized_keys
chmod 600 authorized_keys
chown -R vagrant ~/.ssh
