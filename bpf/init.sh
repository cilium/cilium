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
IP4_HOST=$3
IP6_HOST=$4
MODE=$5
# Only set if MODE = "direct" or "lb"
NATIVE_DEV=$6
XDP_DEV=$7
XDP_MODE=$8
MTU=$9
PRE_EXISTING_DEVICE="${10}"

ID_HOST=1
ID_WORLD=2

# If the value below is changed, be sure to update bugtool/cmd/configuration.go
# as well when dumping the routing table in bugtool. See GH-5828. 
PROXY_RT_TABLE=2005

set -e
set -x

if [[ ! $(command -v cilium) ]]; then
	echo "Can't be initialized because 'cilium' is not in the path."
	exit 1
fi

# Remove old legacy files
rm $RUNDIR/encap.state 2> /dev/null || true

# Enable JIT if compiled into kernel
echo 1 > /proc/sys/net/core/bpf_jit_enable || true

# Disable rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter

# Disable unprivileged BPF
echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled || true

# Docker <17.05 has an issue which causes IPv6 to be disabled in the initns for all
# interface (https://github.com/docker/libnetwork/issues/1720)
# Enable IPv6 for now
echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/globals"

function setup_veth()
{
	local -r NAME=$1

	ip link set $NAME up
	echo 1 > /proc/sys/net/ipv4/conf/${NAME}/forwarding
	echo 1 > /proc/sys/net/ipv6/conf/${NAME}/forwarding
	echo 0 > /proc/sys/net/ipv4/conf/${NAME}/rp_filter
	echo 1 > /proc/sys/net/ipv4/conf/${NAME}/accept_local
	echo 0 > /proc/sys/net/ipv4/conf/${NAME}/send_redirects
}

function setup_veth_pair()
{
	local -r NAME1=$1
	local -r NAME2=$2

	# Only recreate the veth pair if it does not exist already.
	# This avoids problems with changing MAC addresses.
 	if [ "$(ip link show $NAME1 type veth | cut -d ' ' -f 2)" != "${NAME1}@${NAME2}:" ] ; then
		ip link del $NAME1 2> /dev/null || true
		ip link add $NAME1 type veth peer name $NAME2
	fi

	setup_veth $NAME1
	setup_veth $NAME2
}

function move_local_rules_af()
{
	IP=$1

	# Do not move the rule if we don't support the address family
	if [ -z "$($IP rule list)" ]; then
		return
	fi

	# move the local table lookup rule from pref 0 to pref 100 so we can
	# insert the cilium ip rules before the local table. It is strictly
	# required to add the new local rule before deleting the old one as
	# otherwise local addresses will not be reachable for a short period of
	# time.
	$IP rule list | grep 100 | grep "lookup local" || {
		$IP rule add from all lookup local pref 100
	}
	$IP rule del from all lookup local pref 0 2> /dev/null || true

	# check if the move of the local table move was successful and restore
	# it otherwise
	if [ "$($IP rule list | grep "lookup local" | wc -l)" -eq "0" ]; then
		$IP rule add from all lookup local pref 0
		$IP rule del from all lookup local pref 100
		echo "Error: The kernel does not support moving the local table routing rule"
		echo "Local routing rules:"
		$IP rule list lookup local
		exit 1
	fi
}

function move_local_rules()
{
	move_local_rules_af "ip -4"
	move_local_rules_af "ip -6"
}

function setup_proxy_rules()
{
	# Any packet from a local process uses a separate routing table
	rulespec="fwmark 0xA00/0xF00 pref 10 lookup $PROXY_RT_TABLE"

	if [ -n "$(ip -4 rule list)" ]; then
		if [ -z "$(ip -4 rule list $rulespec)" ]; then
			ip -4 rule add $rulespec
		fi
	fi

	if [ -n "$IP4_HOST" ]; then
		ip route replace table $PROXY_RT_TABLE $IP4_HOST/32 dev $HOST_DEV1
		ip route replace table $PROXY_RT_TABLE default via $IP4_HOST
	fi

    # PRE_EXISTING_DEVICE might not have an IPv6 address
    if [ -z "${PRE_EXISTING_DEVICE}" ]; then
        if [ -n "$(ip -6 rule list)" ]; then
            if [ -z "$(ip -6 rule list $rulespec)" ]; then
                ip -6 rule add $rulespec
            fi
        fi

        IP6_LLADDR=$(ip -6 addr show dev $HOST_DEV2 | grep inet6 | head -1 | awk '{print $2}' | awk -F'/' '{print $1}')
        if [ -n "$IP6_LLADDR" ]; then
            ip -6 route replace table $PROXY_RT_TABLE ${IP6_LLADDR}/128 dev $HOST_DEV1
            ip -6 route replace table $PROXY_RT_TABLE default via $IP6_LLADDR dev $HOST_DEV1
        fi
    fi
}

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

	clang -O2 -g -target bpf -emit-llvm				\
	      -Wno-address-of-packed-member -Wno-unknown-warning-option	\
	      -I. -I$DIR -I$LIB/include					\
	      -D__NR_CPUS__=$(nproc)					\
	      -DENABLE_ARP_RESPONDER					\
	      -DHANDLE_NS						\
	      $EXTRA_OPTS						\
	      -c $LIB/$IN -o - |					\
	llc -march=bpf -mcpu=probe -mattr=dwarfris -filetype=$TYPE -o $OUT
}

function xdp_load()
{
	DEV=$1
	MODE=$2
	OPTS=$3
	IN=$4
	OUT=$5
	SEC=$6
	CIDR_MAP=$7

	bpf_compile $IN $OUT obj "$OPTS"

	ip link set dev $DEV $MODE off
	rm -f "$CILIUM_BPF_MNT/xdp/globals/$CIDR_MAP" 2> /dev/null || true
	cilium-map-migrate -s $OUT
	set +e
	ip link set dev $DEV $MODE obj $OUT sec $SEC
	RETCODE=$?
	set -e
	cilium-map-migrate -e $OUT -r $RETCODE
	return $RETCODE
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

	NODE_MAC=$(ip link show $DEV | grep ether | awk '{print $2}')
	NODE_MAC="{.addr=$(mac2array $NODE_MAC)}"

	OPTS="${OPTS} -DNODE_MAC=${NODE_MAC} -DCALLS_MAP=${CALLS_MAP}"
	bpf_compile $IN $OUT obj "$OPTS"

	tc qdisc del dev $DEV clsact 2> /dev/null || true
	tc qdisc add dev $DEV clsact
	cilium-map-migrate -s $OUT
	set +e
	tc filter add dev $DEV $WHERE prio 1 handle 1 bpf da obj $OUT sec $SEC
	RETCODE=$?
	set -e
	cilium-map-migrate -e $OUT -r $RETCODE
	return $RETCODE
}

function encap_fail()
{
	(>&2 echo "ERROR: Setup of encapsulation device $ENCAP_DEV has failed. Is another program using a $MODE device?")
	(>&2 echo "Configured $MODE devices on the system:")
	(>&2 ip link show type $MODE)
	exit 1
}

$LIB/run_probes.sh $LIB $RUNDIR

if [ -n "${PRE_EXISTING_DEVICE}" ]; then
    HOST_DEV1="${PRE_EXISTING_DEVICE}"
    HOST_DEV2="${PRE_EXISTING_DEVICE}"
else
    HOST_DEV1="cilium_host"
    HOST_DEV2="cilium_net"

    setup_veth_pair $HOST_DEV1 $HOST_DEV2

    ip link set $HOST_DEV1 arp off
    ip link set $HOST_DEV2 arp off

    ip link set $HOST_DEV1 mtu $MTU
    ip link set $HOST_DEV2 mtu $MTU
fi

sed -i '/^#.*CILIUM_NET_MAC.*$/d' $RUNDIR/globals/node_config.h
CILIUM_NET_MAC=$(ip link show $HOST_DEV2 | grep ether | awk '{print $2}')
CILIUM_NET_MAC=$(mac2array $CILIUM_NET_MAC)

# Remove the entire '#ifndef ... #endif block
# Each line must contain the string '#.*CILIUM_NET_MAC.*'
sed -i '/^#.*CILIUM_NET_MAC.*$/d' $RUNDIR/globals/node_config.h
echo "#ifndef CILIUM_NET_MAC" >> $RUNDIR/globals/node_config.h
echo "#define CILIUM_NET_MAC { .addr = ${CILIUM_NET_MAC}}" >> $RUNDIR/globals/node_config.h
echo "#endif /* CILIUM_NET_MAC */" >> $RUNDIR/globals/node_config.h

sed -i '/^#.*HOST_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
HOST_IDX=$(cat /sys/class/net/${HOST_DEV2}/ifindex)
echo "#define HOST_IFINDEX $HOST_IDX" >> $RUNDIR/globals/node_config.h

sed -i '/^#.*HOST_IFINDEX_MAC.*$/d' $RUNDIR/globals/node_config.h
HOST_MAC=$(ip link show $HOST_DEV1 | grep ether | awk '{print $2}')
HOST_MAC=$(mac2array $HOST_MAC)
echo "#define HOST_IFINDEX_MAC { .addr = ${HOST_MAC}}" >> $RUNDIR/globals/node_config.h

# If the host does not have an IPv6 address assigned, assign our generated host
# IP to make the host accessible to endpoints
[ -n "$(ip -6 addr show to $IP6_HOST)" ] || {
	ip -6 addr add $IP6_HOST dev $HOST_DEV1
}

if [ -z "${PRE_EXISTING_DEVICE}" ]; then
    if [[ "$IP4_HOST" != "<nil>" ]]; then
        [ -n "$(ip -4 addr show to $IP4_HOST)" ] || {
            ip -4 addr add $IP4_HOST dev $HOST_DEV1 scope link
        }
    fi
fi

# Decrease priority of the rule to identify local addresses
move_local_rules

# Install new rules before local rule to ensure that packets from the proxy are
# using a separate routing table
setup_proxy_rules

sed -i '/ENCAP_GENEVE/d' $RUNDIR/globals/node_config.h
sed -i '/ENCAP_VXLAN/d' $RUNDIR/globals/node_config.h
if [ "$MODE" = "vxlan" ]; then
	echo "#define ENCAP_VXLAN 1" >> $RUNDIR/globals/node_config.h
elif [ "$MODE" = "geneve" ]; then
	echo "#define ENCAP_GENEVE 1" >> $RUNDIR/globals/node_config.h
fi

if [ "$MODE" = "vxlan" -o "$MODE" = "geneve" ]; then
	ENCAP_DEV="cilium_${MODE}"
	ip link show $ENCAP_DEV || {
		ip link add $ENCAP_DEV type $MODE external || encap_fail
	}
	ip link set $ENCAP_DEV up || encap_fail

	ENCAP_IDX=$(cat /sys/class/net/${ENCAP_DEV}/ifindex)
	sed -i '/^#.*ENCAP_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
	echo "#define ENCAP_IFINDEX $ENCAP_IDX" >> $RUNDIR/globals/node_config.h

	CALLS_MAP="cilium_calls_overlay_${ID_WORLD}"
	POLICY_MAP="cilium_policy_reserved_${ID_WORLD}"
	OPTS="-DSECLABEL=${ID_WORLD} -DPOLICY_MAP=${POLICY_MAP}"
	bpf_load $ENCAP_DEV "$OPTS" "ingress" bpf_overlay.c bpf_overlay.o from-overlay ${CALLS_MAP}
else
	# Remove eventual existing encapsulation device from previous run
	ip link del cilium_vxlan 2> /dev/null || true
	ip link del cilium_geneve 2> /dev/null || true
fi

if [ "$MODE" = "direct" ]; then
	if [ -z "$NATIVE_DEV" ]; then
		echo "No device specified for $MODE mode, ignoring..."
	else
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

		CALLS_MAP=cilium_calls_netdev_${ID_WORLD}
		POLICY_MAP="cilium_policy_reserved_${ID_WORLD}"
		OPTS="-DSECLABEL=${ID_WORLD} -DPOLICY_MAP=${POLICY_MAP}"
		bpf_load $NATIVE_DEV "$OPTS" "ingress" bpf_netdev.c bpf_netdev.o from-netdev $CALLS_MAP

		echo "$NATIVE_DEV" > $RUNDIR/device.state
	fi
elif [ "$MODE" = "lb" ]; then
	if [ -z "$NATIVE_DEV" ]; then
		echo "No device specified for $MODE mode, ignoring..."
	else
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

		CALLS_MAP="cilium_calls_lb"
		OPTS="-DLB_L3 -DLB_L4"
		bpf_load $NATIVE_DEV "$OPTS" "ingress" bpf_lb.c bpf_lb.o from-netdev $CALLS_MAP

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
CALLS_MAP="cilium_calls_netdev_ns_${ID_HOST}"
POLICY_MAP="cilium_policy_reserved_${ID_HOST}"
OPTS="-DFROM_HOST -DFIXED_SRC_SECCTX=${ID_HOST} -DSECLABEL=${ID_HOST} -DPOLICY_MAP=${POLICY_MAP}"
bpf_load $HOST_DEV1 "$OPTS" "egress" bpf_netdev.c bpf_host.o from-netdev $CALLS_MAP

if [ -n "$XDP_DEV" ]; then
	CIDR_MAP="cilium_cidr_v*"
	OPTS=""
	xdp_load $XDP_DEV $XDP_MODE "$OPTS" bpf_xdp.c bpf_xdp.o from-netdev $CIDR_MAP
fi
