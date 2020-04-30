#!/bin/bash
#
# Copyright 2016-2020 Authors of Cilium
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
# Only set if MODE = "direct", "ipvlan", "flannel"
NATIVE_DEV=$6
XDP_DEV=$7
XDP_MODE=$8
MTU=$9
IPSEC=${10}
ENCRYPT_DEV=${11}
HOSTLB=${12}
HOSTLB_UDP=${13}
CGROUP_ROOT=${14}
BPFFS_ROOT=${15}
NODE_PORT=${16}
NODE_PORT_BIND=${17}
MCPU=${18}

ID_HOST=1
ID_WORLD=2

# If the value below is changed, be sure to update bugtool/cmd/configuration.go
# as well when dumping the routing table in bugtool. See GH-5828.
PROXY_RT_TABLE=2005
TO_PROXY_RT_TABLE=2004

set -e
set -x
set -o pipefail

if [[ ! $(command -v cilium-map-migrate) ]]; then
	echo "Can't be initialized because 'cilium-map-migrate' is not in the path."
	exit 1
fi

# Remove old legacy files
rm $RUNDIR/encap.state 2> /dev/null || true

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/globals"

function setup_dev()
{
	local -r NAME=$1

	ip link set $NAME up

	if [ "$IP6_HOST" != "<nil>" ]; then
		echo 1 > /proc/sys/net/ipv6/conf/${NAME}/forwarding
	fi

	if [ "$IP4_HOST" != "<nil>" ]; then
		echo 1 > /proc/sys/net/ipv4/conf/${NAME}/forwarding
		echo 0 > /proc/sys/net/ipv4/conf/${NAME}/rp_filter
		echo 1 > /proc/sys/net/ipv4/conf/${NAME}/accept_local
		echo 0 > /proc/sys/net/ipv4/conf/${NAME}/send_redirects
	fi
}

function setup_veth_pair()
{
	local -r NAME1=$1
	local -r NAME2=$2

	# Only recreate the veth pair if it does not exist already.
	# This avoids problems with changing MAC addresses.
 	if [ "$(ip link show $NAME1 type veth | cut -d ' ' -f 2)" != "${NAME1}@${NAME2}:" ] ; then
		ip link del $NAME1 2> /dev/null || true
		ip link add name $NAME1 address $(rnd_mac_addr) type veth \
            peer name $NAME2 address $(rnd_mac_addr)
	fi

	setup_dev $NAME1
	setup_dev $NAME2
}

function setup_ipvlan_slave()
{
	local -r NATIVE_DEV=$1
	local -r HOST_DEV=$2

	# No issues with changing MAC addresses since all ipvlan
	# slaves always inherits MAC from native device.
	ip link del $HOST_DEV 2> /dev/null || true

	ip link add link $NATIVE_DEV name $HOST_DEV type ipvlan mode l3

	setup_dev $HOST_DEV
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
	if [ "$IP4_HOST" != "<nil>" ]; then
		move_local_rules_af "ip -4"
	fi

	if [ "$IP6_HOST" != "<nil>" ]; then
		move_local_rules_af "ip -6"
	fi
}

function setup_proxy_rules()
{
	if [ "$MODE" = "ipvlan" ]; then
		return
	fi

	# Any packet from an ingress proxy uses a separate routing table that routes
	# the packet back to the cilium host device.
	from_ingress_rulespec="fwmark 0xA00/0xF00 pref 10 lookup $PROXY_RT_TABLE"

	# Any packet to an ingress or egress proxy uses a separate routing table
	# that routes the packet to the loopback device regardless of the destination
	# address in the packet. For this to work the ctx must have a socket set
	# (e.g., via TPROXY).
	to_proxy_rulespec="fwmark 0x200/0xF00 pref 9 lookup $TO_PROXY_RT_TABLE"

	if [ "$IP4_HOST" != "<nil>" ]; then
		if [ -n "$(ip -4 rule list)" ]; then
			if [ -z "$(ip -4 rule list $to_proxy_rulespec)" ]; then
				ip -4 rule add $to_proxy_rulespec
			fi
			case "${MODE}" in
			"routed")
				if [ ! -z "$(ip -4 rule list $from_ingress_rulespec)" ]; then
					ip -4 rule delete $from_ingress_rulespec
				fi
				;;
			*)
				if [ -z "$(ip -4 rule list $from_ingress_rulespec)" ]; then
					ip -4 rule add $from_ingress_rulespec
				fi
				;;
			esac
		fi

		# Traffic to the host proxy is local
		ip route replace table $TO_PROXY_RT_TABLE local 0.0.0.0/0 dev lo
		# Traffic from ingress proxy goes to Cilium address space via the cilium host device
		case "${MODE}" in
		"routed")
			ip route delete table $PROXY_RT_TABLE $IP4_HOST/32 dev $HOST_DEV1 2>/dev/null || true
			ip route delete table $PROXY_RT_TABLE default via $IP4_HOST 2>/dev/null || true
			;;
		*)
			ip route replace table $PROXY_RT_TABLE $IP4_HOST/32 dev $HOST_DEV1
			ip route replace table $PROXY_RT_TABLE default via $IP4_HOST
			;;
		esac
	else
		ip -4 rule del $to_proxy_rulespec 2> /dev/null || true
		ip -4 rule del $from_ingress_rulespec 2> /dev/null || true
	fi

	# flannel might not have an IPv6 address
	case "${MODE}" in
		"flannel")
			;;
		*)
			if [ "$IP6_HOST" != "<nil>" ]; then
				if [ -n "$(ip -6 rule list)" ]; then
					if [ -z "$(ip -6 rule list $to_proxy_rulespec)" ]; then
						ip -6 rule add $to_proxy_rulespec
					fi
					case "${MODE}" in
					"routed")
						if [ ! -z "$(ip -6 rule list $from_ingress_rulespec)" ]; then
							ip -6 rule delete $from_ingress_rulespec
						fi
						;;
					*)
						if [ -z "$(ip -6 rule list $from_ingress_rulespec)" ]; then
							ip -6 rule add $from_ingress_rulespec
						fi
						;;
					esac
				fi

				IP6_LLADDR=$(ip -6 addr show dev $HOST_DEV2 | grep inet6 | head -1 | awk '{print $2}' | awk -F'/' '{print $1}')
				if [ -n "$IP6_LLADDR" ]; then
					# Traffic to the host proxy is local
					ip -6 route replace table $TO_PROXY_RT_TABLE local ::/0 dev lo
					# Traffic from ingress proxy goes to Cilium address space via the cilium host device
					case "${MODE}" in
					"routed")
						ip -6 route delete table $PROXY_RT_TABLE ${IP6_LLADDR}/128 dev $HOST_DEV1 2>/dev/null || true
						ip -6 route delete table $PROXY_RT_TABLE default via $IP6_LLADDR dev $HOST_DEV1 2>/dev/null || true
						;;
					*)
						ip -6 route replace table $PROXY_RT_TABLE ${IP6_LLADDR}/128 dev $HOST_DEV1
						ip -6 route replace table $PROXY_RT_TABLE default via $IP6_LLADDR dev $HOST_DEV1
						;;
					esac
				fi
			else
				ip -6 rule del $to_proxy_rulespec 2> /dev/null || true
				ip -6 rule del $from_ingress_rulespec 2> /dev/null || true
			fi
			;;
	esac
}

function mac2array()
{
	echo "{0x${1//:/,0x}}"
}

function rnd_mac_addr()
{
    local lower=$(od /dev/urandom -N5 -t x1 -An | sed 's/ /:/g')
    local upper=$(( 0x$(od /dev/urandom -N1 -t x1 -An | cut -d' ' -f2) & 0xfe | 0x02 ))
    printf '%02x%s' $upper $lower
}

function bpf_compile()
{
	IN=$1
	OUT=$2
	TYPE=$3
	EXTRA_OPTS=$4

	clang -O2 -target bpf -emit-llvm				\
	      -Wall -Wextra -Werror					\
	      -Wno-address-of-packed-member				\
	      -Wno-unknown-warning-option				\
	      -Wno-gnu-variable-sized-type-not-at-end			\
	      -I. -I$DIR -I$LIB -I$LIB/include				\
	      -D__NR_CPUS__=$(nproc)					\
	      -DENABLE_ARP_RESPONDER=1					\
	      -DHANDLE_NS=1						\
	      $EXTRA_OPTS						\
	      -c $LIB/$IN -o - |					\
	llc -march=bpf -mcpu=$MCPU -mattr=dwarfris -filetype=$TYPE -o $OUT
}

function xdp_unload()
{
	DEV=$1
	MODE=$2

	ip link set dev $DEV $MODE off 2> /dev/null || true
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

	NODE_MAC=$(ip link show $DEV | grep ether | awk '{print $2}')
	NODE_MAC="{.addr=$(mac2array $NODE_MAC)}"

	bpf_compile $IN $OUT obj "$OPTS -DNODE_MAC=${NODE_MAC}"
	rm -f "$CILIUM_BPF_MNT/xdp/globals/$CIDR_MAP" 2> /dev/null || true
	cilium-map-migrate -s $OUT
	set +e
	ip -force link set dev $DEV $MODE obj $OUT sec $SEC
	RETCODE=$?
	set -e
	cilium-map-migrate -e $OUT -r $RETCODE
	return $RETCODE
}

function bpf_unload()
{
	DEV=$1
	WHERE=$2

	tc filter del dev $DEV $WHERE 2> /dev/null || true
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
	tc qdisc replace dev $DEV clsact || true
	[ -z "$(tc filter show dev $DEV $WHERE | grep -v 'pref 1 bpf chain 0 $\|pref 1 bpf chain 0 handle 0x1')" ] || tc filter del dev $DEV $WHERE
	cilium-map-migrate -s $OUT
	set +e
	tc filter replace dev $DEV $WHERE prio 1 handle 1 bpf da obj $OUT sec $SEC
	RETCODE=$?
	set -e
	cilium-map-migrate -e $OUT -r $RETCODE
	return $RETCODE
}

function bpf_load_cgroups()
{
	OPTS=$1
	IN=$2
	OUT=$3
	PROG_TYPE=$4
	WHERE=$5
	SEC=$6
	CALLS_MAP=$7
	CGRP=$8
	BPFMNT=$9

	OPTS="${OPTS} -DCALLS_MAP=${CALLS_MAP}"
	bpf_compile $IN $OUT obj "$OPTS"

	TMP_FILE="$BPFMNT/tc/globals/cilium_cgroups_$WHERE"
	rm -f $TMP_FILE

	cilium-map-migrate -s $OUT
	set +e
	tc exec bpf pin $TMP_FILE obj $OUT type $PROG_TYPE attach_type $WHERE sec $SEC
	RETCODE=$?
	set -e
	cilium-map-migrate -e $OUT -r $RETCODE

	if [ "$RETCODE" -eq "0" ]; then
		set +e
		bpftool cgroup attach $CGRP $WHERE pinned $TMP_FILE
		RETCODE=$?
		set -e
		rm -f $TMP_FILE
	fi
	return $RETCODE
}

function bpf_clear_cgroups()
{
	CGRP=$1
	HOOK=$2

	set +e
	ID=$(bpftool cgroup show $CGRP | grep $HOOK | awk '{print $1}')
	set -e
	if [ -n "$ID" ]; then
		bpftool cgroup detach $CGRP $HOOK id $ID
	fi
}

function encap_fail()
{
	(>&2 echo "ERROR: Setup of encapsulation device $ENCAP_DEV has failed. Is another program using a $MODE device?")
	(>&2 echo "Configured $MODE devices on the system:")
	(>&2 ip link show type $MODE)
	exit 1
}

# Base device setup
case "${MODE}" in
	"flannel")
		HOST_DEV1="${NATIVE_DEV}"
		HOST_DEV2="${NATIVE_DEV}"

		setup_dev "${NATIVE_DEV}"
		;;
	"ipvlan")
		HOST_DEV1="cilium_host"
		HOST_DEV2="${HOST_DEV1}"

		setup_ipvlan_slave $NATIVE_DEV $HOST_DEV1

		ip link set $HOST_DEV1 mtu $MTU
		;;
	*)
		HOST_DEV1="cilium_host"
		HOST_DEV2="cilium_net"

		setup_veth_pair $HOST_DEV1 $HOST_DEV2

		ip link set $HOST_DEV1 arp off
		ip link set $HOST_DEV2 arp off

		ip link set $HOST_DEV1 mtu $MTU
		ip link set $HOST_DEV2 mtu $MTU
        ;;
esac

# node_config.h header generation
case "${MODE}" in
	*)
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

		sed -i '/^#.*CILIUM_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
		CILIUM_IDX=$(cat /sys/class/net/${HOST_DEV1}/ifindex)
		echo "#define CILIUM_IFINDEX $CILIUM_IDX" >> $RUNDIR/globals/node_config.h

		CILIUM_EPHEMERAL_MIN=$(cat /proc/sys/net/ipv4/ip_local_port_range | awk '{print $1}')
		echo "#define EPHEMERAL_MIN $CILIUM_EPHEMERAL_MIN" >> $RUNDIR/globals/node_config.h

		if [ "$NODE_PORT" = "true" ]; then
			sed -i '/^#.*NATIVE_DEV_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
			NATIVE_DEV_IDX=$(cat /sys/class/net/${NATIVE_DEV}/ifindex)
			echo "#define NATIVE_DEV_IFINDEX $NATIVE_DEV_IDX" >> $RUNDIR/globals/node_config.h
			sed -i '/^#.*NATIVE_DEV_MAC.*$/d' $RUNDIR/globals/node_config.h
			NATIVE_DEV_MAC=$(ip link show $NATIVE_DEV | grep ether | awk '{print $2}')
			NATIVE_DEV_MAC=$(mac2array $NATIVE_DEV_MAC)
			echo "#define NATIVE_DEV_MAC { .addr = ${NATIVE_DEV_MAC}}" >> $RUNDIR/globals/node_config.h

		fi
esac

# Address management
case "${MODE}" in
	"flannel")
		;;
	*)
		# If the host does not have an IPv6 address assigned, assign our generated host
		# IP to make the host accessible to endpoints
		if [ "$IP6_HOST" != "<nil>" ]; then
			[ -n "$(ip -6 addr show to $IP6_HOST dev $HOST_DEV1)" ] || ip -6 addr add $IP6_HOST dev $HOST_DEV1
		fi
		if [ "$IP4_HOST" != "<nil>" ]; then
			[ -n "$(ip -4 addr show to $IP4_HOST dev $HOST_DEV1)" ] || ip -4 addr add $IP4_HOST dev $HOST_DEV1 scope link
		fi
        ;;
esac

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
		ip link add name $ENCAP_DEV address $(rnd_mac_addr) mtu $MTU type $MODE external || encap_fail
	}

	setup_dev $ENCAP_DEV
	ip link set $ENCAP_DEV up || encap_fail

	ENCAP_IDX=$(cat /sys/class/net/${ENCAP_DEV}/ifindex)
	sed -i '/^#.*ENCAP_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
	echo "#define ENCAP_IFINDEX $ENCAP_IDX" >> $RUNDIR/globals/node_config.h

	CALLS_MAP="cilium_calls_overlay_${ID_WORLD}"
	COPTS="-DSECLABEL=${ID_WORLD} -DFROM_ENCAP_DEV=1"
	if [ "$NODE_PORT" = "true" ]; then
		COPTS="${COPTS} -DLB_L3 -DLB_L4 -DDISABLE_LOOPBACK_LB"
	fi
	bpf_load $ENCAP_DEV "$COPTS" "ingress" bpf_overlay.c bpf_overlay.o from-overlay ${CALLS_MAP}
	bpf_load $ENCAP_DEV "$COPTS" "egress" bpf_overlay.c bpf_overlay.o to-overlay ${CALLS_MAP}
else
	# Remove eventual existing encapsulation device from previous run
	ip link del cilium_vxlan 2> /dev/null || true
	ip link del cilium_geneve 2> /dev/null || true
fi

if [ "$MODE" = "direct" ] || [ "$MODE" = "ipvlan" ] || [ "$MODE" = "routed" ] || [ "$NODE_PORT" = "true" ] ; then
	if [ "$NATIVE_DEV" == "<nil>" ]; then
		echo "No device specified for $MODE mode, ignoring..."
	else
		if [ "$IP6_HOST" != "<nil>" ]; then
			echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
		fi

		CALLS_MAP=cilium_calls_netdev_${ID_WORLD}
		COPTS="-DSECLABEL=${ID_WORLD}"
		if [ "$NODE_PORT" = "true" ]; then
			COPTS="${COPTS} -DLB_L3 -DLB_L4 -DDISABLE_LOOPBACK_LB"
		fi

		bpf_load $NATIVE_DEV "$COPTS" "ingress" bpf_netdev.c bpf_netdev.o "from-netdev" $CALLS_MAP
		if [ "$NODE_PORT" = "true" ]; then
			bpf_load $NATIVE_DEV "$COPTS" "egress" bpf_netdev.c bpf_netdev.o "to-netdev" $CALLS_MAP
		else
			bpf_unload $NATIVE_DEV "egress"
		fi

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

# Remove bpf_netdev.o from previously used devices
for iface in $(ip -o -a l | awk '{print $2}' | cut -d: -f1 | cut -d@ -f1 | grep -v cilium); do
    [ "$iface" == "$NATIVE_DEV" ] && continue
    for where in ingress egress; do
        if tc filter show dev "$iface" "$where" | grep -q "bpf_netdev.o"; then
            echo "Removing bpf_netdev.o from $where of $iface"
            tc filter del dev "$iface" "$where" || true
        fi
    done
done

if [ "$HOSTLB" = "true" ]; then
	if [ "$IP6_HOST" != "<nil>" ]; then
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi

	CALLS_MAP="cilium_calls_lb"
	COPTS="-DLB_L3 -DLB_L4"
	if [ "$IP6_HOST" != "<nil>" ] || [ "$IP4_HOST" != "<nil>" ] && [ -f /proc/sys/net/ipv6/conf/all/forwarding ]; then
		bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr connect6 from-sock6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		if [ "$NODE_PORT" = "true" ] && [ "$NODE_PORT_BIND" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sock post_bind6 post-bind-sock6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT post_bind6
		fi
		if [ "$HOSTLB_UDP" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr sendmsg6 snd-sock6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr recvmsg6 rcv-sock6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT sendmsg6
			bpf_clear_cgroups $CGROUP_ROOT recvmsg6
		fi
	fi
	if [ "$IP4_HOST" != "<nil>" ]; then
		bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr connect4 from-sock4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		if [ "$NODE_PORT" = "true" ] && [ "$NODE_PORT_BIND" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sock post_bind4 post-bind-sock4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT post_bind4
		fi
		if [ "$HOSTLB_UDP" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr sendmsg4 snd-sock4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr recvmsg4 rcv-sock4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT sendmsg4
			bpf_clear_cgroups $CGROUP_ROOT recvmsg4
		fi
	fi
else
	bpf_clear_cgroups $CGROUP_ROOT post_bind4
	bpf_clear_cgroups $CGROUP_ROOT post_bind6
	bpf_clear_cgroups $CGROUP_ROOT connect4
	bpf_clear_cgroups $CGROUP_ROOT connect6
	bpf_clear_cgroups $CGROUP_ROOT sendmsg4
	bpf_clear_cgroups $CGROUP_ROOT sendmsg6
	bpf_clear_cgroups $CGROUP_ROOT recvmsg4
	bpf_clear_cgroups $CGROUP_ROOT recvmsg6
fi

# bpf_host.o requires to see an updated node_config.h which includes ENCAP_IFINDEX
CALLS_MAP="cilium_calls_netdev_ns_${ID_HOST}"
COPTS="-DFROM_HOST -DSECLABEL=${ID_HOST}"
if [ "$MODE" == "ipvlan" ]; then
	COPTS+=" -DENABLE_EXTRA_HOST_DEV"
fi
bpf_load $HOST_DEV1 "$COPTS" "egress" bpf_netdev.c bpf_host.o from-netdev $CALLS_MAP
bpf_load $HOST_DEV1 "" "ingress" bpf_hostdev_ingress.c bpf_hostdev_ingress.o to-host $CALLS_MAP
bpf_load $HOST_DEV2 "" "ingress" bpf_hostdev_ingress.c bpf_hostdev_ingress.o to-host $CALLS_MAP
if [ "$IPSEC" == "true" ]; then
	if [ "$ENCRYPT_DEV" != "<nil>" ]; then
		bpf_load $ENCRYPT_DEV "" "ingress" bpf_network.c bpf_network.o from-network $CALLS_MAP
	fi
fi
if [ "$HOST_DEV1" != "$HOST_DEV2" ]; then
	bpf_unload $HOST_DEV2 "egress"
fi

# Remove bpf_xdp.o from previously used devices
for iface in $(ip -o -a l | awk '{print $2}' | cut -d: -f1 | cut -d@ -f1 | grep -v cilium); do
	[ "$iface" == "$XDP_DEV" ] && continue
	for mode in xdpdrv xdpgeneric; do
		xdp_unload "$iface" "$mode"
	done
done

if [ "$XDP_DEV" != "<nil>" ]; then
	if ip -one link show dev $XDP_DEV | grep -v -q $XDP_MODE; then
		for mode in xdpdrv xdpgeneric; do
			xdp_unload "$XDP_DEV" "$mode"
		done
	fi
	CIDR_MAP="cilium_cidr_v*"
	COPTS="-DSECLABEL=${ID_WORLD} -DCALLS_MAP=cilium_calls_xdp"
	if [ "$NODE_PORT" = "true" ]; then
		COPTS="${COPTS} -DLB_L3 -DLB_L4 -DDISABLE_LOOPBACK_LB"
	fi
	xdp_load $XDP_DEV $XDP_MODE "$COPTS" bpf_xdp.c bpf_xdp.o from-netdev $CIDR_MAP
fi

# Compile dummy BPF file containing all shared struct definitions used by
# pkg/alignchecker to validate C and Go equivalent struct alignments
bpf_compile bpf_alignchecker.c bpf_alignchecker.o obj "-g"
