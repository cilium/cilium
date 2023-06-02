#!/bin/bash
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

# LIB=${1}
RUNDIR=${2}
PROCSYSNETDIR=${3}
SYSCLASSNETDIR=${4}
IP4_HOST=${5}
IP6_HOST=${6}
MODE=${7}
TUNNEL_PROTOCOL=${8}
# Only set if TUNNEL_PROTOCOL = "vxlan", "geneve"
TUNNEL_PORT=${9}
# Only set if MODE = "direct"
NATIVE_DEVS=${10}
HOST_DEV1=${11}
HOST_DEV2=${12}
MTU=${13}
# SOCKETLB=${14}
# SOCKETLB_PEER=${15}
# CGROUP_ROOT=${16}
# BPFFS_ROOT=${17}
NODE_PORT=${18}
# NODE_PORT_BIND=${19}
# MCPU=${20}
# NR_CPUS=${21}
ENDPOINT_ROUTES=${22}
PROXY_RULE=${23}
FILTER_PRIO=${24}
DEFAULT_RTPROTO=${25}
LOCAL_RULE_PRIO=${26}

# If the value below is changed, be sure to update bugtool/cmd/configuration.go
# as well when dumping the routing table in bugtool. See GH-5828.
PROXY_RT_TABLE=2005
TO_PROXY_RT_TABLE=2004

set -e
set -x
set -o pipefail

# Remove old legacy files
rm $RUNDIR/encap.state 2> /dev/null || true

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

	# move the local table lookup rule from pref 0 to pref LOCAL_RULE_PRIO so we
	# can insert the cilium ip rules before the local table. It is strictly
	# required to add the new local rule before deleting the old one as
	# otherwise local addresses will not be reachable for a short period of
	# time.
	$IP rule list | grep "${LOCAL_RULE_PRIO}" | grep "lookup local" || {
		$IP rule add from all lookup local pref ${LOCAL_RULE_PRIO} proto $DEFAULT_RTPROTO
	}
	$IP rule del from all lookup local pref 0 2> /dev/null || true

	# check if the move of the local table move was successful and restore
	# it otherwise
	if [ "$($IP rule list | grep "lookup local" | wc -l)" -eq "0" ]; then
		$IP rule add from all lookup local pref 0 proto $DEFAULT_RTPROTO
		$IP rule del from all lookup local pref ${LOCAL_RULE_PRIO}
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
	# TODO(brb): remove $PROXY_RT_TABLE -related code in v1.15
	from_ingress_rulespec="fwmark 0xA00/0xF00 pref 10 lookup $PROXY_RT_TABLE proto $DEFAULT_RTPROTO"

	# Any packet to an ingress or egress proxy uses a separate routing table
	# that routes the packet to the loopback device regardless of the destination
	# address in the packet. For this to work the ctx must have a socket set
	# (e.g., via TPROXY).
	to_proxy_rulespec="fwmark 0x200/0xF00 pref 9 lookup $TO_PROXY_RT_TABLE proto $DEFAULT_RTPROTO"

	if [ "$IP4_HOST" != "<nil>" ]; then
		if [ -n "$(ip -4 rule list)" ]; then
			if [ -z "$(ip -4 rule list $to_proxy_rulespec)" ]; then
				ip -4 rule add $to_proxy_rulespec
			fi

			ip -4 rule delete $from_ingress_rulespec || true
		fi

		# Traffic to the host proxy is local
		ip route replace table $TO_PROXY_RT_TABLE local 0.0.0.0/0 dev lo proto $DEFAULT_RTPROTO

		# The $PROXY_RT_TABLE is no longer in use, so delete it
		ip route delete table $PROXY_RT_TABLE $IP4_HOST/32 dev $HOST_DEV1 2>/dev/null || true
		ip route delete table $PROXY_RT_TABLE default via $IP4_HOST 2>/dev/null || true
	else
		ip -4 rule del $to_proxy_rulespec 2> /dev/null || true
		ip -4 rule del $from_ingress_rulespec 2> /dev/null || true
	fi

	if [ "$IP6_HOST" != "<nil>" ]; then
		if [ -n "$(ip -6 rule list)" ]; then
			if [ -z "$(ip -6 rule list $to_proxy_rulespec)" ]; then
				ip -6 rule add $to_proxy_rulespec
			fi

			ip -6 rule delete $from_ingress_rulespec || true
		fi

		IP6_LLADDR=$(ip -6 addr show dev $HOST_DEV2 | grep inet6 | head -1 | awk '{print $2}' | awk -F'/' '{print $1}')
		if [ -n "$IP6_LLADDR" ]; then
			# Traffic to the host proxy is local
			ip -6 route replace table $TO_PROXY_RT_TABLE local ::/0 dev lo proto $DEFAULT_RTPROTO
			# The $PROXY_RT_TABLE is no longer in use, so delete it
			ip -6 route delete table $PROXY_RT_TABLE ${IP6_LLADDR}/128 dev $HOST_DEV1 2>/dev/null || true
			ip -6 route delete table $PROXY_RT_TABLE default via $IP6_LLADDR dev $HOST_DEV1 2>/dev/null || true
		fi
	else
		ip -6 rule del $to_proxy_rulespec 2> /dev/null || true
		ip -6 rule del $from_ingress_rulespec 2> /dev/null || true
	fi
}

function rnd_mac_addr()
{
    local lower=$(od /dev/urandom -N5 -t x1 -An | sed 's/ /:/g')
    local upper=$(( 0x$(od /dev/urandom -N1 -t x1 -An | cut -d' ' -f2) & 0xfe | 0x02 ))
    printf '%02x%s' $upper $lower
}

function create_encap_dev()
{
	TUNNEL_OPTS="external"
	if [ "${TUNNEL_PORT}" != "<nil>" ]; then
		TUNNEL_OPTS="dstport $TUNNEL_PORT $TUNNEL_OPTS"
	fi
	ip link add name $ENCAP_DEV address $(rnd_mac_addr) type $TUNNEL_PROTOCOL $TUNNEL_OPTS || encap_fail
}

function encap_fail()
{
	(>&2 echo "ERROR: Setup of encapsulation device $ENCAP_DEV has failed. Is another program using a $MODE device?")
	(>&2 echo "Configured $MODE devices on the system:")
	(>&2 ip link show type $MODE)
	exit 1
}

	# If the host does not have an IPv6 address assigned, assign our generated host
	# IP to make the host accessible to endpoints
	if [ "$IP6_HOST" != "<nil>" ]; then
		[ -n "$(ip -6 addr show to $IP6_HOST dev $HOST_DEV1)" ] || ip -6 addr add $IP6_HOST dev $HOST_DEV1
	fi
	if [ "$IP4_HOST" != "<nil>" ]; then
		[ -n "$(ip -4 addr show to $IP4_HOST dev $HOST_DEV1)" ] || ip -4 addr add $IP4_HOST dev $HOST_DEV1
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

# Remove eventual existing encapsulation device from previous run
case "${TUNNEL_PROTOCOL}" in
  "<nil>")
	ip link del cilium_vxlan 2> /dev/null || true
	ip link del cilium_geneve 2> /dev/null || true
    ;;
  "vxlan")
	ip link del cilium_geneve 2> /dev/null || true
    ;;
  "geneve")
	ip link del cilium_vxlan 2> /dev/null || true
    ;;
  *)
	(>&2 echo "ERROR: Unknown tunnel mode")
    exit 1
    ;;
esac

if [ "${TUNNEL_PROTOCOL}" != "<nil>" ]; then
	ENCAP_DEV="cilium_${TUNNEL_PROTOCOL}"

	ip link show $ENCAP_DEV || create_encap_dev

	if [ "${TUNNEL_PORT}" != "<nil>" ]; then
		ip -details link show $ENCAP_DEV | grep "dstport $TUNNEL_PORT" || {
			ip link delete name $ENCAP_DEV type $TUNNEL_PROTOCOL
			create_encap_dev
		}
	fi

	ip link set $ENCAP_DEV mtu $MTU || encap_fail
	setup_dev $ENCAP_DEV || encap_fail

	ENCAP_IDX=$(cat "${SYSCLASSNETDIR}/${ENCAP_DEV}/ifindex")
	sed -i '/^#.*ENCAP_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
	echo "#define ENCAP_IFINDEX $ENCAP_IDX" >> $RUNDIR/globals/node_config.h
fi

if [ "$MODE" = "direct" ] || [ "$NODE_PORT" = "true" ] ; then
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
		# iproute2 uses the filename and section (bpf_overlay.o:[from-overlay]) as
		# the filter name. Filters created by the Go bpf loader contain the bpf
		# function and interface name, like cil_from_netdev-eth0.
		# Only detach programs known to be attached to 'physical' network devices.
		if tc filter show dev "$iface" "$where" | grep -qE "\b(bpf_host|cil_from_netdev|cil_to_netdev)"; then
			echo "Removing $where TC filter from interface $iface"
			tc filter del dev "$iface" "$where" || true
		fi
	done
done

if [ "$HOST_DEV1" != "$HOST_DEV2" ]; then
	tc filter del dev $HOST_DEV2 "egress" 2> /dev/null || true
fi
