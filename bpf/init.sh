#!/bin/bash
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

LIB=${1}
RUNDIR=${2}
PROCSYSNETDIR=${3}
SYSCLASSNETDIR=${4}
IP4_HOST=${5}
IP6_HOST=${6}
MODE=${7}
TUNNEL_MODE=${8}
# Only set if TUNNEL_MODE = "vxlan", "geneve"
TUNNEL_PORT=${9}
# Only set if MODE = "direct", "ipvlan"
NATIVE_DEVS=${10}
HOST_DEV1=${11}
HOST_DEV2=${12}
MTU=${13}
HOSTLB=${14}
HOSTLB_UDP=${15}
HOSTLB_PEER=${16}
CGROUP_ROOT=${17}
BPFFS_ROOT=${18}
NODE_PORT=${19}
NODE_PORT_BIND=${20}
MCPU=${21}
NR_CPUS=${22}
ENDPOINT_ROUTES=${23}
PROXY_RULE=${24}
FILTER_PRIO=${25}

ID_HOST=1
ID_WORLD=2

# If the value below is changed, be sure to update bugtool/cmd/configuration.go
# as well when dumping the routing table in bugtool. See GH-5828.
PROXY_RT_TABLE=2005
TO_PROXY_RT_TABLE=2004

set -e
set -x
set -o pipefail

# Remove old legacy files
rm $RUNDIR/encap.state 2> /dev/null || true

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/globals"

function setup_dev()
{
	local -r NAME=$1

	ip link set $NAME up

	if [ "$IP6_HOST" != "<nil>" ]; then
		echo 1 > "${PROCSYSNETDIR}/ipv6/conf/${NAME}/forwarding"
	fi

	if [ "$IP4_HOST" != "<nil>" ]; then
		echo 1 > "${PROCSYSNETDIR}/ipv4/conf/${NAME}/forwarding"
		echo 0 > "${PROCSYSNETDIR}/ipv4/conf/${NAME}/rp_filter"
		echo 1 > "${PROCSYSNETDIR}/ipv4/conf/${NAME}/accept_local"
		echo 0 > "${PROCSYSNETDIR}/ipv4/conf/${NAME}/send_redirects"
	fi
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
			if [ "$ENDPOINT_ROUTES" = "true" ]; then
				if [ ! -z "$(ip -4 rule list $from_ingress_rulespec)" ]; then
					ip -4 rule delete $from_ingress_rulespec
				fi
			else
				if [ -z "$(ip -4 rule list $from_ingress_rulespec)" ]; then
					ip -4 rule add $from_ingress_rulespec
				fi
			fi
		fi

		# Traffic to the host proxy is local
		ip route replace table $TO_PROXY_RT_TABLE local 0.0.0.0/0 dev lo
		# Traffic from ingress proxy goes to Cilium address space via the cilium host device
		if [ "$ENDPOINT_ROUTES" = "true" ]; then
			ip route delete table $PROXY_RT_TABLE $IP4_HOST/32 dev $HOST_DEV1 2>/dev/null || true
			ip route delete table $PROXY_RT_TABLE default via $IP4_HOST 2>/dev/null || true
		else
			ip route replace table $PROXY_RT_TABLE $IP4_HOST/32 dev $HOST_DEV1
			ip route replace table $PROXY_RT_TABLE default via $IP4_HOST
		fi
	else
		ip -4 rule del $to_proxy_rulespec 2> /dev/null || true
		ip -4 rule del $from_ingress_rulespec 2> /dev/null || true
	fi

	if [ "$IP6_HOST" != "<nil>" ]; then
		if [ -n "$(ip -6 rule list)" ]; then
			if [ -z "$(ip -6 rule list $to_proxy_rulespec)" ]; then
				ip -6 rule add $to_proxy_rulespec
			fi
			if [ "$ENDPOINT_ROUTES" = "true" ]; then
				if [ ! -z "$(ip -6 rule list $from_ingress_rulespec)" ]; then
					ip -6 rule delete $from_ingress_rulespec
				fi
			else
				if [ -z "$(ip -6 rule list $from_ingress_rulespec)" ]; then
					ip -6 rule add $from_ingress_rulespec
				fi
			fi
		fi

		IP6_LLADDR=$(ip -6 addr show dev $HOST_DEV2 | grep inet6 | head -1 | awk '{print $2}' | awk -F'/' '{print $1}')
		if [ -n "$IP6_LLADDR" ]; then
			# Traffic to the host proxy is local
			ip -6 route replace table $TO_PROXY_RT_TABLE local ::/0 dev lo
			# Traffic from ingress proxy goes to Cilium address space via the cilium host device
			if [ "$ENDPOINT_ROUTES" = "true" ]; then
				ip -6 route delete table $PROXY_RT_TABLE ${IP6_LLADDR}/128 dev $HOST_DEV1 2>/dev/null || true
				ip -6 route delete table $PROXY_RT_TABLE default via $IP6_LLADDR dev $HOST_DEV1 2>/dev/null || true
			else
				ip -6 route replace table $PROXY_RT_TABLE ${IP6_LLADDR}/128 dev $HOST_DEV1
				ip -6 route replace table $PROXY_RT_TABLE default via $IP6_LLADDR dev $HOST_DEV1
			fi
		fi
	else
		ip -6 rule del $to_proxy_rulespec 2> /dev/null || true
		ip -6 rule del $from_ingress_rulespec 2> /dev/null || true
	fi
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

	clang -O2 -target bpf -std=gnu89 -nostdinc -emit-llvm	\
	      -g -Wall -Wextra -Werror -Wshadow			\
	      -Wno-address-of-packed-member			\
	      -Wno-unknown-warning-option			\
	      -Wno-gnu-variable-sized-type-not-at-end		\
	      -Wdeclaration-after-statement			\
	      -Wimplicit-int-conversion -Wenum-conversion	\
	      -I. -I$DIR -I$LIB -I$LIB/include			\
	      -D__NR_CPUS__=$NR_CPUS				\
	      -DENABLE_ARP_RESPONDER=1				\
	      $EXTRA_OPTS					\
	      -c $LIB/$IN -o - |				\
	llc -march=bpf -mcpu=$MCPU -mattr=dwarfris -filetype=$TYPE -o $OUT
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
	[ -z "$(tc filter show dev $DEV $WHERE | grep -v "pref $FILTER_PRIO bpf chain 0 $\|pref $FILTER_PRIO bpf chain 0 handle 0x1")" ] || tc filter del dev $DEV $WHERE

	cilium bpf migrate-maps -s "$OUT"

	if ! tc filter replace dev "$DEV" "$WHERE" prio "$FILTER_PRIO" handle 1 bpf da obj "$OUT" sec "$SEC"; then
		cilium bpf migrate-maps -e "$OUT" -r 1
		return 1
	fi
}

function bpf_load_cgroups()
{
	OPTS=$1
	IN=$2
	OUT=$3
	PROG_TYPE=$4
	WHERE=$5
	CALLS_MAP=$6
	CGRP=$7
	BPFMNT=$8

	OPTS="${OPTS} -DCALLS_MAP=${CALLS_MAP}"
	bpf_compile $IN $OUT obj "$OPTS"

	TMP_FILE="$BPFMNT/tc/globals/cilium_cgroups_$WHERE"
	rm -f $TMP_FILE

	cilium bpf migrate-maps -s "$OUT"

	if ! tc exec bpf pin "$TMP_FILE" obj "$OUT" type "$PROG_TYPE" attach_type "$WHERE" sec "cgroup/$WHERE"; then
		cilium bpf migrate-maps -e "$OUT" -r 1
		return 1
	fi

	if ! bpftool cgroup attach "$CGRP" "$WHERE" pinned "$TMP_FILE"; then
		rm -f "$TMP_FILE"
		cilium bpf migrate-maps -e "$OUT" -r 1
		return 1
	fi
}

function bpf_clear_cgroups()
{
	CGRP=$1
	HOOK=$2

	set +e
	ID=$(bpftool cgroup show $CGRP | grep -w $HOOK | awk '{print $1}')
	set -e
	if [ -n "$ID" ]; then
		bpftool cgroup detach $CGRP $HOOK id $ID
	fi
}

function create_encap_dev()
{
	TUNNEL_OPTS="external"
	if [ "${TUNNEL_PORT}" != "<nil>" ]; then
		TUNNEL_OPTS="dstport $TUNNEL_PORT $TUNNEL_OPTS"
	fi
	ip link add name $ENCAP_DEV address $(rnd_mac_addr) type $TUNNEL_MODE $TUNNEL_OPTS || encap_fail
}

function encap_fail()
{
	(>&2 echo "ERROR: Setup of encapsulation device $ENCAP_DEV has failed. Is another program using a $MODE device?")
	(>&2 echo "Configured $MODE devices on the system:")
	(>&2 ip link show type $MODE)
	exit 1
}

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
		HOST_IDX=$(cat "${SYSCLASSNETDIR}/${HOST_DEV2}/ifindex")
		echo "#define HOST_IFINDEX $HOST_IDX" >> $RUNDIR/globals/node_config.h

		sed -i '/^#.*HOST_IFINDEX_MAC.*$/d' $RUNDIR/globals/node_config.h
		HOST_MAC=$(ip link show $HOST_DEV1 | grep ether | awk '{print $2}')
		HOST_MAC=$(mac2array $HOST_MAC)
		echo "#define HOST_IFINDEX_MAC { .addr = ${HOST_MAC}}" >> $RUNDIR/globals/node_config.h

		sed -i '/^#.*CILIUM_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
		CILIUM_IDX=$(cat "${SYSCLASSNETDIR}/${HOST_DEV1}/ifindex")
		echo "#define CILIUM_IFINDEX $CILIUM_IDX" >> $RUNDIR/globals/node_config.h

		CILIUM_EPHEMERAL_MIN=$(cat "${PROCSYSNETDIR}/ipv4/ip_local_port_range" | awk '{print $1}')
		echo "#define EPHEMERAL_MIN $CILIUM_EPHEMERAL_MIN" >> $RUNDIR/globals/node_config.h
esac

	# If the host does not have an IPv6 address assigned, assign our generated host
	# IP to make the host accessible to endpoints
	if [ "$IP6_HOST" != "<nil>" ]; then
		[ -n "$(ip -6 addr show to $IP6_HOST dev $HOST_DEV1)" ] || ip -6 addr add $IP6_HOST dev $HOST_DEV1
	fi
	if [ "$IP4_HOST" != "<nil>" ]; then
		[ -n "$(ip -4 addr show to $IP4_HOST dev $HOST_DEV1)" ] || ip -4 addr add $IP4_HOST dev $HOST_DEV1 scope link
	fi

if [ "$PROXY_RULE" = "true" ]; then
# Decrease priority of the rule to identify local addresses
move_local_rules

# Install new rules before local rule to ensure that packets from the proxy are
# using a separate routing table
setup_proxy_rules
fi

if [ "$MODE" = "ipip" ]; then
	if [ "$IP4_HOST" != "<nil>" ]; then
		ENCAP_DEV="cilium_ipip4"
		ip link show $ENCAP_DEV || {
			# Upon module load it will create a non-removable tunl0
			# device. Instead of creating an additional useless one,
			# rename tunl0 with cilium prefix in a second step. If
			# we to do 'ip link add name $ENCAP_DEV [...]' it would
			# create two devices. :/
			ip link add name tunl0 type ipip external || true
			ip link set tunl0 name $ENCAP_DEV
		}
		setup_dev $ENCAP_DEV || encap_fail

		ENCAP_IDX=$(cat "${SYSCLASSNETDIR}/${ENCAP_DEV}/ifindex")
		sed -i '/^#.*ENCAP4_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
		echo "#define ENCAP4_IFINDEX $ENCAP_IDX" >> $RUNDIR/globals/node_config.h
	else
		ip link del cilium_ipip4 2> /dev/null || true
	fi
	if [ "$IP6_HOST" != "<nil>" ]; then
		ENCAP_DEV="cilium_ipip6"
		ip link show $ENCAP_DEV || {
			# For cilium_ipip6 device, we unfortunately cannot use the
			# same workaround as cilium_ipip4. While the latter allows
			# to set an existing tunl0 into collect_md mode, the default
			# ip6tnl0 if present cannot. It's quite annoying, but if v6
			# was built into the kernel, we might just need to live with
			# it. Default device creation can still be worked around
			# via boot param if the sysctl from agent won't do it.
			ip link add name $ENCAP_DEV type ip6tnl external || true
			ip link set sit0 name cilium_sit || true
		}
		setup_dev $ENCAP_DEV || encap_fail

		ENCAP_IDX=$(cat "${SYSCLASSNETDIR}/${ENCAP_DEV}/ifindex")
		sed -i '/^#.*ENCAP6_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
		echo "#define ENCAP6_IFINDEX $ENCAP_IDX" >> $RUNDIR/globals/node_config.h
	else
		ip link del cilium_ipip6 2> /dev/null || true
		ip link del cilium_sit   2> /dev/null || true
	fi
else
	ip link del cilium_ipip4 2> /dev/null || true
	ip link del cilium_ipip6 2> /dev/null || true
	ip link del cilium_sit   2> /dev/null || true
fi

if [ "$MODE" = "tunnel" ]; then
	sed -i '/^#.*TUNNEL_MODE.*$/d' $RUNDIR/globals/node_config.h
	echo "#define TUNNEL_MODE 1" >> $RUNDIR/globals/node_config.h
fi

if [ "${TUNNEL_MODE}" != "<nil>" ]; then
	ENCAP_DEV="cilium_${TUNNEL_MODE}"

	ip link show $ENCAP_DEV || create_encap_dev
	ip link set $ENCAP_DEV mtu $MTU || encap_fail

	if [ "${TUNNEL_PORT}" != "<nil>" ]; then
		ip -details link show $ENCAP_DEV | grep "dstport $TUNNEL_PORT" || {
			ip link delete name $ENCAP_DEV type $TUNNEL_MODE
			create_encap_dev
		}
	fi

	setup_dev $ENCAP_DEV || encap_fail

	ENCAP_IDX=$(cat "${SYSCLASSNETDIR}/${ENCAP_DEV}/ifindex")
	sed -i '/^#.*ENCAP_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
	echo "#define ENCAP_IFINDEX $ENCAP_IDX" >> $RUNDIR/globals/node_config.h

	CALLS_MAP="cilium_calls_overlay_${ID_WORLD}"
	COPTS="-DSECLABEL=${ID_WORLD} -DFROM_ENCAP_DEV=1"
	if [ "$NODE_PORT" = "true" ]; then
		COPTS="${COPTS} -DDISABLE_LOOPBACK_LB"
	fi

	bpf_load "$ENCAP_DEV" "$COPTS" ingress bpf_overlay.c bpf_overlay.o from-overlay "$CALLS_MAP"
	bpf_load "$ENCAP_DEV" "$COPTS" egress bpf_overlay.c bpf_overlay.o to-overlay "$CALLS_MAP"

	cilium bpf migrate-maps -e bpf_overlay.o -r 0

else
	# Remove eventual existing encapsulation device from previous run
	ip link del cilium_vxlan 2> /dev/null || true
	ip link del cilium_geneve 2> /dev/null || true
fi

if [ "$MODE" = "direct" ] || [ "$MODE" = "ipvlan" ] || [ "$NODE_PORT" = "true" ] ; then
	if [ "$NATIVE_DEVS" == "<nil>" ]; then
		echo "No device specified for $MODE mode, ignoring..."
	else
		if [ "$IP6_HOST" != "<nil>" ]; then
			echo 1 > "${PROCSYSNETDIR}/ipv6/conf/all/forwarding"
		fi
		echo "$NATIVE_DEVS" > $RUNDIR/device.state
	fi
else
	FILE=$RUNDIR/device.state
	if [ -f $FILE ]; then
		DEVS=$(cat $FILE)
		for DEV in ${DEVS//,/ }; do
			echo "Removed BPF program from device $DEV"
			tc qdisc del dev $DEV clsact 2> /dev/null || true
		done
		rm $FILE
	fi
fi

# Remove bpf_host.o from previously used devices
for iface in $(ip -o -a l | awk '{print $2}' | cut -d: -f1 | cut -d@ -f1 | grep -v cilium); do
	found=false
	for NATIVE_DEV in ${NATIVE_DEVS//;/ }; do
		if [ "${iface}" == "$NATIVE_DEV" ]; then
			found=true
			break
		fi
	done
	$found && continue
	for where in ingress egress; do
		if tc filter show dev "$iface" "$where" | grep -q "bpf_netdev.*[.]o"; then
			echo "Removing bpf_netdev.o from $where of $iface"
			tc filter del dev "$iface" "$where" || true
		fi
		if tc filter show dev "$iface" "$where" | grep -q "bpf_host.o"; then
			echo "Removing bpf_host.o from $where of $iface"
			tc filter del dev "$iface" "$where" || true
		fi
	done
done

if [ "$HOSTLB" = "true" ]; then
	if [ "$IP6_HOST" != "<nil>" ]; then
		echo 1 > "${PROCSYSNETDIR}/ipv6/conf/all/forwarding"
	fi

	CALLS_MAP="cilium_calls_lb"
	COPTS=""
	if [ "$IP6_HOST" != "<nil>" ] || [ "$IP4_HOST" != "<nil>" ] && [ -f "${PROCSYSNETDIR}/ipv6/conf/all/forwarding" ]; then
		bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr connect6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		if [ "$HOSTLB_PEER" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr getpeername6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		fi
		if [ "$NODE_PORT" = "true" ] && [ "$NODE_PORT_BIND" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sock post_bind6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT post_bind6
		fi
		if [ "$MODE" = "ipip" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr bind6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT bind6
		fi
		if [ "$HOSTLB_UDP" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr sendmsg6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr recvmsg6 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT sendmsg6
			bpf_clear_cgroups $CGROUP_ROOT recvmsg6
		fi
	fi
	if [ "$IP4_HOST" != "<nil>" ]; then
		bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr connect4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		if [ "$HOSTLB_PEER" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr getpeername4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		fi
		if [ "$NODE_PORT" = "true" ] && [ "$NODE_PORT_BIND" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sock post_bind4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT post_bind4
		fi
		if [ "$MODE" = "ipip" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr bind4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT bind4
		fi
		if [ "$HOSTLB_UDP" = "true" ]; then
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr sendmsg4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
			bpf_load_cgroups "$COPTS" bpf_sock.c bpf_sock.o sockaddr recvmsg4 $CALLS_MAP $CGROUP_ROOT $BPFFS_ROOT
		else
			bpf_clear_cgroups $CGROUP_ROOT sendmsg4
			bpf_clear_cgroups $CGROUP_ROOT recvmsg4
		fi
	fi

	cilium bpf migrate-maps -e bpf_sock.o -r 0

else
	bpf_clear_cgroups $CGROUP_ROOT bind4
	bpf_clear_cgroups $CGROUP_ROOT bind6
	bpf_clear_cgroups $CGROUP_ROOT post_bind4
	bpf_clear_cgroups $CGROUP_ROOT post_bind6
	bpf_clear_cgroups $CGROUP_ROOT connect4
	bpf_clear_cgroups $CGROUP_ROOT connect6
	bpf_clear_cgroups $CGROUP_ROOT sendmsg4
	bpf_clear_cgroups $CGROUP_ROOT sendmsg6
	bpf_clear_cgroups $CGROUP_ROOT recvmsg4
	bpf_clear_cgroups $CGROUP_ROOT recvmsg6
	bpf_clear_cgroups $CGROUP_ROOT getpeername4
	bpf_clear_cgroups $CGROUP_ROOT getpeername6
fi

if [ "$HOST_DEV1" != "$HOST_DEV2" ]; then
	bpf_unload $HOST_DEV2 "egress"
fi

# Compile dummy BPF file containing all shared struct definitions used by
# pkg/alignchecker to validate C and Go equivalent struct alignments
bpf_compile bpf_alignchecker.c bpf_alignchecker.o obj ""
