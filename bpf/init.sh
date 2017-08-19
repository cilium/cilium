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
TUNNEL_MODE=${10}
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

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/globals"

function mac2array()
{
	echo "{0x${1//:/,0x}}"
}

function bpf_compile()
{
	IN=$1
	OUT=$2
	TYPE=$3
	EXTRA_OPTS=$4

	clang -O2 -target bpf -emit-llvm				\
	      -Wno-address-of-packed-member -Wno-unknown-warning-option	\
	      -I. -I$DIR -I$LIB/include					\
	      -D__NR_CPUS__=$(nproc)					\
	      -DENABLE_ARP_RESPONDER					\
	      -DHANDLE_NS						\
	      $EXTRA_OPTS						\
	      -c $LIB/$IN -o - |					\
	llc -march=bpf -mcpu=probe -filetype=$TYPE -o $OUT
}

function bpf_load()
{
	DEV=$1
	OPTS=$2
	WHERE=$3
	IN=$4
	OUT=$5
	SEC=$6
	CALLS_MAP=$7
	SKIP_DEL=$8

	NODE_MAC=$(ip link show $DEV | grep ether | awk '{print $2}')
	NODE_MAC="{.addr=$(mac2array $NODE_MAC)}"

	OPTS="${OPTS} -DNODE_MAC=${NODE_MAC} -DCALLS_MAP=${CALLS_MAP}"
	bpf_compile $IN $OUT obj "$OPTS"

	if [ -z "$SKIP_DEL" ]; then
		tc qdisc del dev $DEV clsact 2> /dev/null || true
		tc qdisc add dev $DEV clsact
	fi
	rm "/sys/fs/bpf/tc/globals/$CALLS_MAP" 2> /dev/null || true
	tc filter add dev $DEV $WHERE prio 1 handle 1 bpf da obj $OUT sec $SEC
}

function delete_old_ip_rules()
{
	TBL=$1
	for i in $(ip rule list | grep "lookup $TBL" | awk -F: '{print $1}'); do
		ip rule del pref $i;
	done
}

function setup_veth()
{
	local -r NAME=$1

	ip link set $NAME up
	sysctl -w net.ipv4.conf.${NAME}.forwarding=1
	sysctl -w net.ipv6.conf.${NAME}.forwarding=1
	sysctl -w net.ipv4.conf.${NAME}.rp_filter=0
	sysctl -w net.ipv4.conf.${NAME}.accept_local=1
	sysctl -w net.ipv4.conf.${NAME}.send_redirects=0
}

function setup_veth_pair()
{
	local -r NAME1=$1
	local -r NAME2=$2

	ip link del $NAME1 2> /dev/null || true
	ip link add $NAME1 type veth peer name $NAME2

	setup_veth $NAME1
	setup_veth $NAME2
}

function define_mac_in_header()
{
	local -r IFACE=$1
	local -r DEFINE=$2

	MAC=$(ip link show $IFACE | grep ether | awk '{print $2}')
	sed -i "/^#define ${DEFINE}.*$/d" $RUNDIR/globals/node_config.h
	echo "#define ${DEFINE} {.addr=$(mac2array $MAC)}" >> $RUNDIR/globals/node_config.h
}

function setup_nat_box()
{
	# create NAT ingress veth pair
	setup_veth_pair cilium-nat-in cilium-nat-in2
	define_mac_in_header cilium-nat-in NAT_IN_MAC

	CALLS_MAP="cilium_calls_nat_rev_out"
	OPTS="-DCALLS_MAP=$CALLS_MAP"
	bpf_load cilium-nat-in "$OPTS" "egress" bpf_nat_rev_out.c bpf_nat_rev_out.o to-netdev $CALLS_MAP

	# create NAT egress veth pair
	setup_veth_pair cilium-nat-out cilium-nat-out2
	define_mac_in_header cilium-nat-out2 NAT_OUT_MAC

	NAT_OUT_IDX=$(cat /sys/class/net/cilium-nat-out/ifindex)
	sed -i '/^#define NAT_OUT_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
	echo "#define NAT_OUT_IFINDEX $NAT_OUT_IDX" >> $RUNDIR/globals/node_config.h

	CALLS_MAP="cilium_calls_netdev_nat_out"
	OPTS="-DCALLS_MAP=$CALLS_MAP -DFROM_NAT"
	bpf_load cilium-nat-out "$OPTS" "ingress" bpf_netdev.c bpf_netdev_nat_out.o from-netdev $CALLS_MAP

	# delete old ip rules rules
	delete_old_ip_rules 2000
	delete_old_ip_rules 2001

	# move the local table lookup rule from pref 0 to pref 100 so we can
	# insert the cilium ip rules before the local table. It is strictly
	# required to add the new local rule before deleting the old one as
	# otherwise local addresses will not be reachable for a short period of
	# time.
	ip rule list from all lookup local pref 100 | grep "lookup local" || {
		ip rule add from all lookup local pref 100
	}
	ip rule del from all lookup local pref 0 2> /dev/null || true

	# check if the move of the local table move was successful and restore
	# it otherwise
	if [ "$(ip rule list lookup local | wc -l)" -eq "0" ]; then
		ip rule add from all lookup local pref 0
		ip rule del from all lookup local pref 100
		echo "Error: The kernel does not support moving the local table routing rule"
		echo "Local routing rules:"
		ip rule list lookup local
		exit 1
	fi

	ip rule add fwmark 0xA5B80000/0xFFFF0000 pref 10 lookup 2000
	ip rule add fwmark 0xFEFE0000/0xFFFF0000 pref 11 lookup 2001
	ip rule add iif cilium-nat-out2 pref 12 lookup 2001

	if [ -n "$IP4_HOST" ]; then
		ip route add table 2000 $IP4_HOST/32 dev cilium-nat-out2
		ip route add table 2000 default via $IP4_HOST
		ip route add table 2001 $IP4_HOST/32 dev cilium-nat-in
		ip route add table 2001 default via $IP4_HOST
	fi

	# route all forward NAT packets via link-local address of cilium-nat-out
	IP6_LLADDR=$(ip -6 addr show dev cilium-nat-out | grep inet6 | head -1 | awk '{print $2}' | awk -F'/' '{print $1}')
	if [ -n "$IP6_LLADDR" ]; then
		ip -6 route add table 2000 ${IP6_LLADDR}/128 dev cilium-nat-out2
		ip -6 route add table 2000 default via $IP6_LLADDR dev cilium-nat-out2
	fi

	# route all reverse NAT packets via link-local address of cilium-nat-in
	IP6_LLADDR=$(ip -6 addr show dev cilium-nat-in | grep inet6 | head -1 | awk '{print $2}' | awk -F'/' '{print $1}')
	if [ -n "$IP6_LLADDR" ]; then
		ip -6 route add table 2001 ${IP6_LLADDR}/128 dev cilium-nat-in2
		ip -6 route add table 2001 default via $IP6_LLADDR dev cilium-nat-in2
	fi
}

HOST_DEV1="cilium_host"
HOST_DEV2="cilium_net"

$LIB/run_probes.sh $LIB $RUNDIR

ip link del $HOST_DEV1 2> /dev/null || true
ip link add $HOST_DEV1 type veth peer name $HOST_DEV2

ip link set $HOST_DEV1 up
ip link set $HOST_DEV1 arp off
ip link set $HOST_DEV2 up
ip link set $HOST_DEV2 arp off

sysctl -w net.ipv4.conf.${HOST_DEV1}.rp_filter=0
sysctl -w net.ipv4.conf.${HOST_DEV2}.rp_filter=0

sed -i '/^#.*HOST_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
HOST_IDX=$(cat /sys/class/net/${HOST_DEV2}/ifindex)
echo "#define HOST_IFINDEX $HOST_IDX" >> $RUNDIR/globals/node_config.h

sed -i '/^#.*HOST_IFINDEX_MAC.*$/d' $RUNDIR/globals/node_config.h
HOST_MAC=$(ip link show $HOST_DEV1 | grep ether | awk '{print $2}')
HOST_MAC=$(mac2array $HOST_MAC)

# Remove the entire '#ifndef ... #endif block
# Each line must contain the string '#.*HOST_IFINDEX_MAC.*'
sed -i '/^#.*HOST_IFINDEX_MAC.*$/d' $RUNDIR/globals/node_config.h
echo "#ifndef HOST_IFINDEX_MAC" >> $RUNDIR/globals/node_config.h
echo "#define HOST_IFINDEX_MAC { .addr = ${HOST_MAC}}" >> $RUNDIR/globals/node_config.h
echo "#endif /* HOST_IFINDEX_MAC */" >> $RUNDIR/globals/node_config.h

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

if [[ "$IP4_HOST" != "<nil>" ]]; then
  ip -4 addr show $IP4_HOST || {
  ip -4 addr add $IP4_HOST dev $HOST_DEV1
}
fi

ip addr del 169.254.254.1/32 dev $HOST_DEV1 2> /dev/null || true
ip addr add 169.254.254.1/32 dev $HOST_DEV1
ip route del 169.254.254.0/24 dev $HOST_DEV1 2> /dev/null || true
ip route add 169.254.254.0/24 dev $HOST_DEV1 scope link
ip route del $IP4_RANGE 2> /dev/null || true
if [[ "$IP4_HOST" != "<nil>" ]]; then
  ip route add $IP4_RANGE via 169.254.254.1 src $IP4_HOST
fi

if [ "$IP4_SVC_RANGE" != "auto" ]; then
	ip route del $IP4_SVC_RANGE 2> /dev/null || true
        if [[ "$IP4_HOST" != "<nil>" ]]; then
          ip route add $IP4_SVC_RANGE via 169.254.254.1 src $IP4_HOST
        fi
fi

setup_nat_box

if [ "$TUNNEL_MODE" != "disabled" ]; then
	ENCAP_DEV="cilium_${TUNNEL_MODE}"
	ip link show $ENCAP_DEV || {
		ip link add $ENCAP_DEV type $TUNNEL_MODE external
	}
	ip link set $ENCAP_DEV up

	ENCAP_IDX=$(cat /sys/class/net/${ENCAP_DEV}/ifindex)
	sed -i '/^#.*ENCAP_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
	echo "#define ENCAP_IFINDEX $ENCAP_IDX" >> $RUNDIR/globals/node_config.h

	ID=$(cilium identity get $WORLD_ID 2> /dev/null)
	CALLS_MAP="cilium_calls_overlay_${ID}"
	OPTS="-DSECLABEL=${ID} -DPOLICY_MAP=cilium_policy_reserved_${ID}"
	bpf_load $ENCAP_DEV "$OPTS" "ingress" bpf_overlay.c bpf_overlay.o from-overlay ${CALLS_MAP}
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

if [ "$NATIVE_DEV" != "disabled" ]; then
	sysctl -w net.ipv6.conf.all.forwarding=1
	ID=$(cilium identity get $WORLD_ID 2> /dev/null)
	CALLS_MAP=cilium_calls_netdev_${ID}
	OPTS="-DSECLABEL=${ID} -DPOLICY_MAP=cilium_policy_reserved_${ID}"
	bpf_load $NATIVE_DEV "$OPTS" "ingress" bpf_netdev.c bpf_netdev.o from-netdev $CALLS_MAP

	CALLS_MAP="cilium_calls_netdev_tx_${ID}"
	OPTS="-DCALLS_MAP=$CALLS_MAP"
	bpf_load $NATIVE_DEV "$OPTS" "egress" bpf_netdev_tx.c bpf_netdev_tx.o to-netdev $CALLS_MAP skip-del

	echo "$NATIVE_DEV" > $RUNDIR/device.state
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
CALLS_MAP="cilium_calls_netdev_ns_${ID}"
OPTS="-DFROM_HOST -DFIXED_SRC_SECCTX=${ID} -DSECLABEL=${ID} -DPOLICY_MAP=cilium_policy_reserved_${ID}"
bpf_load $HOST_DEV1 "$OPTS" "egress" bpf_netdev.c bpf_host.o from-netdev $CALLS_MAP
