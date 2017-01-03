#!/bin/bash
#
# Copyright 2016 Authors of Cilium
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
ADDR=$3
V4ADDR=$4
MODE=$5

# Only set if MODE = "direct" or "lb"
NATIVE_DEV=$6

HOST_ID="host"
WORLD_ID="world"

set -e
set -x

# Enable JIT
echo 1 > /proc/sys/net/core/bpf_jit_enable

# Disable rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter

function mac2array()
{
	echo "{0x${1//:/,0x}}"
}

function bpf_compile()
{
	DEV=$1
	OPTS=$2
	IN=$3
	OUT=$4

	NODE_MAC=$(ip link show $DEV | grep ether | awk '{print $2}')
	NODE_MAC="{.addr=$(mac2array $NODE_MAC)}"

	clang $CLANG_OPTS $OPTS -DNODE_MAC=${NODE_MAC} -c $LIB/$IN -o $OUT

	tc qdisc del dev $DEV clsact 2> /dev/null || true
	tc qdisc add dev $DEV clsact
	tc filter add dev $DEV ingress bpf da obj $OUT sec $5
}

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/globals"
CLANG_OPTS="-D__NR_CPUS__=$(nproc) -O2 -target bpf -I$DIR -I. -I$LIB/include -DENABLE_ARP_RESPONDER -DHANDLE_NS"

HOST_DEV1="cilium_host"
HOST_DEV2="cilium_net"

$LIB/run_probes.sh $LIB $RUNDIR

ip link show $HOST_DEV1 || {
	ip link add $HOST_DEV1 type veth peer name $HOST_DEV2
}

ip link set $HOST_DEV1 up
ip link set $HOST_DEV1 arp off
ip link set $HOST_DEV2 up
ip link set $HOST_DEV2 arp off

HOST_IDX=$(cat /sys/class/net/${HOST_DEV2}/ifindex)
echo "#define HOST_IFINDEX $HOST_IDX" >> $RUNDIR/globals/node_config.h

HOST_MAC=$(ip link show $HOST_DEV1 | grep ether | awk '{print $2}')
HOST_MAC=$(mac2array $HOST_MAC)
echo "#define HOST_IFINDEX_MAC { .addr = ${HOST_MAC}}" >> $RUNDIR/globals/node_config.h

ID=$(cilium policy get-id $HOST_ID 2> /dev/null)
OPTS="-DFIXED_SRC_SECCTX=${ID} -DSECLABEL=${ID} -DPOLICY_MAP=cilium_policy_reserved_${ID}"

bpf_compile $HOST_DEV2 "$OPTS" bpf_netdev.c bpf_netdev_ns.o from-netdev

HOST_IP=$(echo $ADDR | sed 's/:0$/:ffff/')
ip addr del $HOST_IP/128 dev $HOST_DEV1 2> /dev/null || true
ip addr add $HOST_IP/128 dev $HOST_DEV1

ip route del $ADDR/128 dev $HOST_DEV1 2> /dev/null || true
ip route add $ADDR/128 dev $HOST_DEV1
ip route del $ADDR/112 via $ADDR 2> /dev/null || true
ip route add $ADDR/112 via $ADDR

V4RANGE=$(echo $V4ADDR | sed 's/.[0-9].[0-9]$/.0.0/')
ip route del $V4RANGE/16 via $V4ADDR 2> /dev/null || true
ip route del $V4ADDR/32 dev $HOST_DEV1 2> /dev/null || true
ip addr del $V4ADDR/32 dev $HOST_DEV1 2> /dev/null || true

ip route add $V4ADDR/32 dev $HOST_DEV1
ip route add $V4RANGE/16 via $V4ADDR
# Address needs to added after /32 route and /16 prefix route for some unknown reason
ip addr add $V4ADDR/32 dev $HOST_DEV1

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

	ID=$(cilium policy get-id $WORLD_ID 2> /dev/null)
	OPTS="-DSECLABEL=${ID} -DPOLICY_MAP=cilium_policy_reserved_${ID}"
	bpf_compile $ENCAP_DEV "$OPTS" bpf_overlay.c bpf_overlay.o from-overlay
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

		ID=$(cilium policy get-id $WORLD_ID 2> /dev/null)
		OPTS="-DSECLABEL=${ID} -DPOLICY_MAP=cilium_policy_reserved_${ID}"
		bpf_compile $NATIVE_DEV "$OPTS" bpf_netdev.c bpf_netdev.o from-netdev

		echo "$NATIVE_DEV" > $RUNDIR/device.state
	fi
elif [ "$MODE" = "lb" ]; then
	if [ -z "$NATIVE_DEV" ]; then
		echo "No device specified for direct mode, ignoring..."
	else
		sysctl -w net.ipv6.conf.all.forwarding=1

		OPTS="-DLB_L3 -DLB_L4"
		bpf_compile $NATIVE_DEV "$OPTS" bpf_lb.c bpf_lb.o from-netdev

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
