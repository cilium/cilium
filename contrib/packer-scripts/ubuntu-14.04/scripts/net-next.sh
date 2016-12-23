#!/bin/bash

set -e

mkdir -p $HOME/bin

cat > $HOME/bin/kcompile.sh << "EOF"
#!/bin/bash

apt-get update
apt-get -y install git vim
apt-get -y install libssl-dev libelf-dev
apt-get -y install pkg-config bison flex

cd $HOME
rm -Rf net-next
git clone git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git
cd net-next
rm -Rf .git
cp /boot/config-`uname -r` .config
yes '' | make oldconfig > /dev/null
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
./scripts/config --enable CONFIG_IPV6_OPTIMISTIC_DAD

# build latest kernel
make -j `getconf _NPROCESSORS_ONLN` LOCALVERSION=-custom
EOF

chmod 755 $HOME/bin/kcompile.sh
$HOME/bin/kcompile.sh

cat > $HOME/bin/kinstall.sh << "EOF"
#!/bin/bash

# clean all old kernels
rm -Rf /lib/modules/*
rm /boot/*

cd $HOME/net-next
make modules_install
make install
make headers_install INSTALL_HDR_PATH=/usr/

make -C tools/perf
make -C tools/perf install

#remove kernel sources
cd $HOME
rm -Rf $HOME/net-next
EOF

chmod 755 $HOME/bin/kinstall.sh
$HOME/bin/kinstall.sh

# Temporary hack for Ubuntu
cp /usr/include/asm/unistd* /usr/include/x86_64-linux-gnu/asm/
echo 9p >> /etc/modules
echo 9pnet_virtio >> /etc/modules
echo 9pnet >> /etc/modules


# iproute2 installation
cat > $HOME/bin/iproute2.sh << "EOF"
#!/bin/bash

apt-get update
apt-get -y install git vim
apt-get -y install libssl-dev libelf-dev
apt-get -y install pkg-config bison flex
apt-get -y install gcc-multilib

cd $HOME
git clone -b net-next git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git
cd iproute2/
./configure
make -j `getconf _NPROCESSORS_ONLN`
make install

# delete iproute2 sources
rm -Rf $HOME/iproute2
EOF

chmod 755 $HOME/bin/iproute2.sh
$HOME/bin/iproute2.sh

cat > $HOME/bin/iptables_cleanup.sh << "EOF"
#!/bin/bash

iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -P PREROUTING ACCEPT
iptables -t mangle -P INPUT ACCEPT
iptables -t mangle -P FORWARD ACCEPT
iptables -t mangle -P OUTPUT ACCEPT
iptables -t mangle -P POSTROUTING ACCEPT
iptables -t mangle -F
iptables -t mangle -X
iptables -t filter -P INPUT ACCEPT
iptables -t filter -P FORWARD ACCEPT
iptables -t filter -P OUTPUT ACCEPT
iptables -t filter -F
iptables -t filter -X

ufw disable

rmmod ipt_REJECT nf_reject_ipv4 iptable_mangle ipt_MASQUERADE iptable_nat nf_nat_ipv4 iptable_filter ip6table_filter ip6_tables ip_tables xt_CHECKSUM xt_tcpudp xt_conntrack xt_addrtype ebtable_nat ebtables x_tables nf_nat_masquerade_ipv4 nf_conntrack_ipv4 nf_defrag_ipv4 nf_nat nf_conntrack
EOF

# script to be run by vagrant startup
chmod 755 $HOME/bin/iptables_cleanup.sh

# cleanup
apt-get -y remove build-essential bc pkg-config bison flex
apt-get -y autoremove
apt-get clean
