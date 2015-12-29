#!/bin/bash

apt-get update
apt-get -y install git
cd $HOME
git clone git://git.breakpoint.cc/dborkman/net-next.git
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

# cleanup
apt-get -y remove git build-essential bc
apt-get -y autoremove
apt-get clean

# delete kernel sources
rm -Rf $HOME/net-next
