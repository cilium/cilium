#!/bin/bash
#
# Copyright 2016-2017 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LIB=$1
RUNDIR=$2
IP6_ROUTER=$3
IP4_HOST=$4
IP6_HOST=$5
IP4_RANGE=$6
IP6_RANGE=$7
IP4_SVC_RANGE=$8
IP6_SVC_RANGE=$9
MODE=${10}
# Only set if MODE = "direct" or "lb"
NATIVE_DEV=${11}

HOST_ID="host"
WORLD_ID="world"

set -e
set -x

if [[ ! $(command -v cilium) ]]; then
	echo "Can't be initialized because 'cilium' is not in the path."
	exit 1
fi

# Enable JIT
echo 1 > /proc/sys/net/core/bpf_jit_enable

# Disable rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter

# Docker <17.05 has an issue which causes IPv6 to be disabled in the initns for all
# interface (https://github.com/docker/libnetwork/issues/1720)
# Enable IPv6 for now
sysctl -w net.ipv6.conf.all.disable_ipv6=0

function mac2array()
{
	echo "{0x${1//:/,0x}}"
}

function bpf_compile()
{
	DEV=$1
	OPTS=$2
	WHERE=$3
	IN=$4
	OUT=$5
	SEC=$6

	NODE_MAC=$(ip link show $DEV | grep ether | awk '{print $2}')
	NODE_MAC="{.addr=$(mac2array $NODE_MAC)}"

	clang $CLANG_OPTS $OPTS -DNODE_MAC=${NODE_MAC} -c $LIB/$IN -o $OUT

	tc qdisc del dev $DEV clsact 2> /dev/null || true
	tc qdisc add dev $DEV clsact
	tc filter add dev $DEV $WHERE prio 1 handle 1 bpf da obj $OUT sec $SEC
}

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/globals"
CLANG_OPTS="-D__NR_CPUS__=$(nproc) -O2 -target bpf -I$DIR -I. -I$LIB/include -DENABLE_ARP_RESPONDER -DHANDLE_NS -Wno-address-of-packed-member -Wno-unknown-warning-option"

HOST_DEV1="cilium_host"
HOST_DEV2="cilium_net"

$LIB/run_probes.sh $LIB $RUNDIR

ip link del $HOST_DEV1 2> /dev/null || true
ip link add $HOST_DEV1 type veth peer name $HOST_DEV2

ip link set $HOST_DEV1 up
ip link set $HOST_DEV1 arp off
ip link set $HOST_DEV2 up
ip link set $HOST_DEV2 arp off

HOST_IDX=$(cat /sys/class/net/${HOST_DEV2}/ifindex)
echo "#define HOST_IFINDEX $HOST_IDX" >> $RUNDIR/globals/node_config.h

HOST_MAC=$(ip link show $HOST_DEV1 | grep ether | awk '{print $2}')
HOST_MAC=$(mac2array $HOST_MAC)
echo "#define HOST_IFINDEX_MAC { .addr = ${HOST_MAC}}" >> $RUNDIR/globals/node_config.h

# If the host does not have an IPv6 address assigned, assign our generated host
# IP to make the host accessible to endpoints
ip -6 addr show $IP6_HOST || {
	ip -6 addr add $IP6_HOST dev $HOST_DEV1
}

ip route del $IP6_ROUTER/128 2> /dev/null || true
ip route add $IP6_ROUTER/128 dev $HOST_DEV1
ip route del $IP6_RANGE 2> /dev/null || true
ip route add $IP6_RANGE via $IP6_ROUTER src $IP6_HOST

if [ "$IP6_SVC_RANGE" != "auto" ]; then
	ip route del $IP6_SVC_RANGE 2> /dev/null || true
	ip route add $IP6_SVC_RANGE via $IP6_ROUTER src $IP6_HOST
fi

ip -4 addr show $IP4_HOST || {
	ip -4 addr add $IP4_HOST dev $HOST_DEV1
}

ip addr del 169.254.254.1/32 dev $HOST_DEV1 2> /dev/null || true
ip addr add 169.254.254.1/32 dev $HOST_DEV1
ip route del 169.254.254.0/24 dev $HOST_DEV1 2> /dev/null || true
ip route add 169.254.254.0/24 dev $HOST_DEV1 scope link
ip route del $IP4_RANGE 2> /dev/null || true
ip route add $IP4_RANGE via 169.254.254.1 src $IP4_HOST

if [ "$IP4_SVC_RANGE" != "auto" ]; then
	ip route del $IP4_SVC_RANGE 2> /dev/null || true
	ip route add $IP4_SVC_RANGE via 169.254.254.1 src $IP4_HOST
fi

sed '/ENCAP_GENEVE/d' $RUNDIR/globals/node_config.h
sed '/ENCAP_VXLAN/d' $RUNDIR/globals/node_config.h
if [ "$MODE" = "vxlan" ]; then
	echo "#define ENCAP_VXLAN 1" >> $RUNDIR/globals/node_config.h
elif [ "$MODE" = "geneve" ]; then
	echo "#define ENCAP_GENEVE 1" >> $RUNDIR/globals/node_config.h
fi

if [ "$MODE" = "vxlan" -o "$MODE" = "geneve" ]; then
	ENCAP_DEV="cilium_${MODE}"
	ip link show $ENCAP_DEV || {
		ip link add $ENCAP_DEV type $MODE external
	}
	ip link set $ENCAP_DEV up

	ENCAP_IDX=$(cat /sys/class/net/${ENCAP_DEV}/ifindex)
	sed '/ENCAP_IFINDEX/d' $RUNDIR/globals/node_config.h
	echo "#define ENCAP_IFINDEX $ENCAP_IDX" >> $RUNDIR/globals/node_config.h

	ID=$(cilium identity get $WORLD_ID 2> /dev/null)
	OPTS="-DSECLABEL=${ID} -DPOLICY_MAP=cilium_policy_reserved_${ID} -DCALLS_MAP=cilium_calls_overlay_${ID}"
	bpf_compile $ENCAP_DEV "$OPTS" "ingress" bpf_overlay.c bpf_overlay.o from-overlay
	echo "$ENCAP_DEV" > $RUNDIR/encap.state
else
	FILE=$RUNDIR/encap.state
	if [ -f $FILE ]; then
		DEV=$(cat $FILE)
		echo "Removed BPF program from device $DEV"
		tc qdisc del dev $DEV clsact 2> /dev/null || true
		rm $FILE
	fi
fi

if [ "$MODE" = "direct" ]; then
	if [ -z "$NATIVE_DEV" ]; then
		echo "No device specified for direct mode, ignoring..."
	else
		sysctl -w net.ipv6.conf.all.forwarding=1

		ID=$(cilium identity get $WORLD_ID 2> /dev/null)
		OPTS="-DSECLABEL=${ID} -DPOLICY_MAP=cilium_policy_reserved_${ID} -DCALLS_MAP=cilium_calls_netdev_${ID}"
		bpf_compile $NATIVE_DEV "$OPTS" "ingress" bpf_netdev.c bpf_netdev.o from-netdev

		echo "$NATIVE_DEV" > $RUNDIR/device.state
	fi
elif [ "$MODE" = "lb" ]; then
	if [ -z "$NATIVE_DEV" ]; then
		echo "No device specified for direct mode, ignoring..."
	else
		sysctl -w net.ipv6.conf.all.forwarding=1

		OPTS="-DLB_L3 -DLB_L4 -DCALLS_MAP=cilium_calls_lb_${ID}"
		bpf_compile $NATIVE_DEV "$OPTS" "ingress" bpf_lb.c bpf_lb.o from-netdev

		echo "$NATIVE_DEV" > $RUNDIR/device.state
	fi
else
	FILE=$RUNDIR/device.state
	if [ -f $FILE ]; then
		DEV=$(cat $FILE)
		echo "Removed BPF program from device $DEV"
		tc qdisc del dev $DEV clsact 2> /dev/null || true
		rm $FILE
	fi
fi

# bpf_host.o requires to see an updated node_config.h which includes ENCAP_IFINDEX
ID=$(cilium identity get $HOST_ID 2> /dev/null)
OPTS="-DFROM_HOST -DFIXED_SRC_SECCTX=${ID} -DSECLABEL=${ID} -DPOLICY_MAP=cilium_policy_reserved_${ID} -DCALLS_MAP=cilium_calls_netdev_ns_${ID}"
bpf_compile $HOST_DEV1 "$OPTS" "egress" bpf_netdev.c bpf_host.o from-netdev
