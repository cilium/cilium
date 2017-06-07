#!/bin/bash
#
# Test Topology:
#  2.2.2.2/32 via 3.3.3.3 src $(ip of cilium_host)
#  f00d::1:1/128 via fbfb::10:10
#        |
#        v
#  veth lbtest1    <-----> veth lbtest2
#  fbfb::10:10/128           |
#  3.3.3.3/32                +-> ingress bpf_lb (ENCAP_IFINDEX=...)
#                                           |
#                                           +---> cilium_vxlan

source "./helpers.bash"

set -e

TEST_NET="cilium"
NETPERF_IMAGE="tgraf/netperf"
ENCAP_DEV="cilium_vxlan"

logs_clear

function cleanup {
	docker rm -f server1 server2 server3 server4 server5 client misc 2> /dev/null || true
	rm netdev_config.h tmp_lb.o 2> /dev/null || true
	rm /sys/fs/bpf/tc/globals/lbtest 2> /dev/null || true
	ip link del lbtest1 2> /dev/null || true
}

function mac2array()
{
	echo "{0x${1//:/,0x}}"
}

function host_ip6()
{
	ip -6 addr show cilium_host scope global | grep inet6 | awk '{print $2}' | sed -e 's/\/.*//'
}

function host_ip4()
{
	ip -4 addr show cilium_host scope global | grep inet | awk '{print $2}' | sed -e 's/\/.*//'
}

trap cleanup EXIT

# Remove containers from a previously incomplete run
cleanup

set -x

#cilium config Debug=true DropNotification=true

# Test the addition and removal of services with and without daemon

# Clean everything first
cilium service delete --all
cilium service list

ip link add lbtest1 type veth peer name lbtest2
ip link set lbtest1 up

# Route f00d::1:1 IPv6 packets to a fantasy router ("fbfb::10:10") behind lbtest1
ip -6 route add fbfb::10:10/128 dev lbtest1
MAC=$(ip link show lbtest1 | grep ether | awk '{print $2}')
ip neigh add fbfb::10:10 lladdr $MAC dev lbtest1
ip -6 route add f00d::1:1/128 via fbfb::10:10

# Route 2.2.2.2 IPv4 packets to a fantasy router ("3.3.3.3") behind lbtest1
SRC=$(ip addr show dev cilium_host | grep 'inet ' | awk '{print $2}' | sed 's/\/32//')
ip route add 3.3.3.3/32 dev lbtest1
MAC=$(ip link show lbtest1 | grep ether | awk '{print $2}')
ip neigh add 3.3.3.3 lladdr $MAC dev lbtest1
ip route add 2.2.2.2/32 via 3.3.3.3 src $SRC

ENCAP_IDX=$(cat /sys/class/net/${ENCAP_DEV}/ifindex)

ip link set lbtest2 up
LIB=/var/lib/cilium/bpf
RUN=/var/run/cilium/state
NH_IFINDEX=$(cat /sys/class/net/cilium_host/ifindex)
NH_MAC=$(ip link show cilium_host | grep ether | awk '{print $2}')
NH_MAC="{.addr=$(mac2array $NH_MAC)}"
CLANG_OPTS="-D__NR_CPUS__=$(nproc) -DNODE_MAC=$NH_MAC -DLB_L3 -DENCAP_IFINDEX=$ENCAP_IDX -DLB_DSTMAC=$NH_MAC -DCALLS_MAP=lbtest -O2 -target bpf -I. -I$LIB/include -I$RUN/globals -DDEBUG -Wno-address-of-packed-member -Wno-unknown-warning-option"
touch netdev_config.h
clang $CLANG_OPTS -c $LIB/bpf_lb.c -o tmp_lb.o

tc qdisc del dev lbtest2 clsact 2> /dev/null || true
tc qdisc add dev lbtest2 clsact
tc filter add dev lbtest2 ingress prio 1 handle 1 bpf da obj tmp_lb.o sec from-netdev

docker network inspect $TEST_NET 2> /dev/null || {
	docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

docker run -dt --net=$TEST_NET --name server1 -l id.server -l server1 httpd
docker run -dt --net=$TEST_NET --name server2 -l id.server -l server2 httpd
docker run -dt --net=$TEST_NET --name server3 -l id.server -l server3 httpd
docker run -dt --net=$TEST_NET --name server4 -l id.server -l server4 httpd
docker run -dt --net=$TEST_NET --name server5 -l id.server -l server5 httpd
docker run -dt --net=$TEST_NET --name client -l id.client tgraf/nettools
docker run -dt --net=$TEST_NET --name misc   -l id.client borkmann/misc

# FIXME IPv6 DAD period
sleep 5

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_IP | awk '{ print $1}')

SERVER1_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server1)
SERVER1_ID=$(cilium endpoint list | grep $SERVER1_IP | awk '{ print $1}')
SERVER1_IP4=$(cilium endpoint list | grep $SERVER1_IP | awk '{ print $6}')

SERVER2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server2)
SERVER2_ID=$(cilium endpoint list | grep $SERVER2_IP | awk '{ print $1}')
SERVER2_IP4=$(cilium endpoint list | grep $SERVER2_IP | awk '{ print $6}')

SERVER3_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server3)
SERVER3_ID=$(cilium endpoint list | grep $SERVER3_IP | awk '{ print $1}')
SERVER3_IP4=$(cilium endpoint list | grep $SERVER3_IP | awk '{ print $6}')

SERVER4_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server4)
SERVER4_ID=$(cilium endpoint list | grep $SERVER4_IP | awk '{ print $1}')
SERVER4_IP4=$(cilium endpoint list | grep $SERVER4_IP | awk '{ print $6}')

SERVER5_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server5)
SERVER5_ID=$(cilium endpoint list | grep $SERVER5_IP | awk '{ print $1}')
SERVER5_IP4=$(cilium endpoint list | grep $SERVER5_IP | awk '{ print $6}')

cilium endpoint config $CLIENT_ID  | grep ConntrackLocal
cilium endpoint config $SERVER1_ID | grep ConntrackLocal
cilium endpoint config $SERVER2_ID | grep ConntrackLocal
cilium endpoint config $SERVER3_ID | grep ConntrackLocal
cilium endpoint config $SERVER4_ID | grep ConntrackLocal
cilium endpoint config $SERVER5_ID | grep ConntrackLocal

#IFACE=$(ip link | grep lxc | sed -e 's/.* \(lxc[^@]*\).*/\1/')
#for name in $IFACE; do
#	ethtool -k $name tso off gso off gro off
#done

cilium policy delete --all 2> /dev/null || true
cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:world":""}},
	    {"matchLabels":{"id.client":""}},
	    {"matchLabels":{"id.server":""}}
	]
    }]
}]
EOF

# Clear eventual old entries, this may fail if the maps have not been created
cilium service delete --all || true
cilium service list

# We can also use multiple --backends that will get appended.
SVC_IP6="f00d::1:1"
cilium service update --rev --frontend "[$SVC_IP6]:0" --id 222 \
                        --backends "[$SERVER1_IP]:0" \
                        --backends "[$SERVER2_IP]:0"

SVC_IP4="2.2.2.2"
cilium service update --rev --frontend "$SVC_IP4:0"  --id 223 \
			--backends "$SERVER1_IP4:0" \
			--backends "$SERVER2_IP4:0"

LB_HOST_IP6="f00d::1:2"
cilium service update --rev --frontend "[$LB_HOST_IP6]:0" --id 224 \
			--backends "[$(host_ip6)]:0"

LB_HOST_IP4="3.3.3.3"
cilium service update --rev --frontend "$LB_HOST_IP4:0" --id 225 \
			--backends "$(host_ip4):0"

cilium service list

## Test 1: local host => bpf_lb => local container
ping $SVC_IP4 -c 4 || {
	abort "Error: Unable to ping"
}

ping6 $SVC_IP6 -c 4 || {
	abort "Error: Unable to ping"
}

cleanup
cilium policy delete --all
