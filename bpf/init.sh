#!/bin/bash
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

# LIB=${1}
RUNDIR=${2}
# PROCSYSNETDIR=${3}
# SYSCLASSNETDIR=${4}
IP4_HOST=${5}
IP6_HOST=${6}
# MODE=${7}
# TUNNEL_PROTOCOL=${8}
# Only set if TUNNEL_PROTOCOL = "vxlan", "geneve"
# TUNNEL_PORT=${9}
# Only set if MODE = "direct"
# NATIVE_DEVS=${10}
HOST_DEV1=${11}
HOST_DEV2=${12}
# MTU=${13}
# SOCKETLB=${14}
# SOCKETLB_PEER=${15}
# CGROUP_ROOT=${16}
# BPFFS_ROOT=${17}
# NODE_PORT=${18}
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

if [ "$PROXY_RULE" = "true" ]; then
# Decrease priority of the rule to identify local addresses
move_local_rules

# Install new rules before local rule to ensure that packets from the proxy are
# using a separate routing table
setup_proxy_rules
fi

