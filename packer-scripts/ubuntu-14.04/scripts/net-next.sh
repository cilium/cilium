#!/bin/bash

apt-get update
apt-get -y install git vim
apt-get -y install libssl-dev libelf-dev

cd $HOME
git clone -b ebpf-madhu git://git.breakpoint.cc/dborkman/net-next.git
cd net-next
rm -Rf .git
cp /boot/config-`uname -r` .config
yes '' | make oldconfig
./scripts/config --disable CONFIG_DEBUG_INFO
./scripts/config --disable CONFIG_DEBUG_KERNEL
./scripts/config --enable CONFIG_BPF
./scripts/config --enable CONFIG_BPF_SYSCALL
./scripts/config --module CONFIG_NETFILTER_XT_MATCH_BPF
./scripts/config --module CONFIG_NET_CLS_BPF
./scripts/config --module CONFIG_NET_ACT_BPF
./scripts/config --enable CONFIG_BPF_JIT
./scripts/config --enable CONFIG_HAVE_BPF_JIT
./scripts/config --enable CONFIG_BPF_EVENTS
./scripts/config --module CONFIG_TEST_BPF
./scripts/config --disable CONFIG_LUSTRE_FS

# make and install latest kernel
make -j `getconf _NPROCESSORS_ONLN` LOCALVERSION=-custom

# clean all old kernels
rm -Rf /lib/modules/*
rm /boot/*

make modules_install
make install
make headers_install INSTALL_HDR_PATH=/usr/

# Temporary hack for Ubuntu
cp /usr/include/asm/unistd* /usr/include/x86_64-linux-gnu/asm/

# delete kernel sources
rm -Rf $HOME/net-next

# iproute2 installation
apt-get -y install pkg-config bison flex
cd $HOME
git clone git://git.breakpoint.cc/dborkman/iproute2.git
cd iproute2/
git checkout ebpf-madhu
./configure
make -j `getconf _NPROCESSORS_ONLN`
make install

# delete iproute2 sources
rm -Rf $HOME/iproute2

# cleanup
apt-get -y remove build-essential bc pkg-config bison flex
apt-get -y autoremove
apt-get clean
