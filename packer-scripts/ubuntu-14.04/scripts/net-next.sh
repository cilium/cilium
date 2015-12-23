#!/bin/bash

apt-get -y install git build-essential kernel-package fakeroot libncurses5-dev libssl-dev ccache bc
cd $HOME
git clone git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git
cd net-next
cp /boot/config-`uname -r` .config
yes '' | make oldconfig
./scripts/config --enable CONFIG_NET_ACT_BPF
./scripts/config --disable CONFIG_LUSTRE_FS
make -j `getconf _NPROCESSORS_ONLN` LOCALVERSION=-custom
make modules_install
make install
shutdown -r now
sleep 60
