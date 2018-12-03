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

# This script creates a network namespace, configures the network connectivity
# for it, then runs a command within the namespace and waits for the command
# to exit. Cleans up the namespace and device configuration on termination.
# Must be run as root.
#
# Example: $ spawn_netns.sh mynetns mynetns-dev host-dev "fc00::1/64" \
#            "192.168.0.100/24" ping "8.8.8.8"

NETNS=$1
HOSTDEV=$2
NETNSDEV=$3
IP6=$4
IP4=$5
TARGET=$6
TARGET_ARGS=$7

configure_netns()
{
	ip netns add ${NETNS}
	ip li set dev ${HOSTDEV} up
	ip li set dev ${NETNSDEV} netns ${NETNS}
	ip netns exec ${NETNS} ip li set dev ${NETNSDEV} up
	if [ "${IP6}" != "" ]; then
		ip netns exec ${NETNS} ip addr add dev ${NETNSDEV} ${IP6}
	fi
	if [ "${IP4}" != "" ]; then
		ip netns exec ${NETNS} ip addr add dev ${NETNSDEV} ${IP4}
	fi
	ip netns exec ${NETNS} ip li set dev lo up
}

cleanup()
{
	ip netns exec ${NETNS} ip li set dev ${NETNSDEV} down
	if [ "${IP6}" != "" ]; then
		ip netns exec ${NETNS} ip addr del dev ${NETNSDEV} ${IP6}
	fi
	if [ "${IP4}" != "" ]; then
		ip netns exec ${NETNS} ip addr del dev ${NETNSDEV} ${IP4}
	fi
	ip netns exec ${NETNS} ip li set dev ${NETNSDEV} netns 1
	ip netns del ${NETNS}
}

netns_exists()
{
	ip netns list | grep -q ${NETNS}
}

run_target()
{
	ip netns exec ${NETNS} ${TARGET} ${TARGET_ARGS}
}

invalid_dev()
{
	! ip link show $1 2>&1 >/dev/null
}

validate_args()
{
	if [ $# -lt 6 ]; then
		echo "Usage: $0 <netns> <veth> <peer> <ip6/cidr> <ip4/cidr> <target> [<target-args>]" >&2
		exit 1
	fi
	if ip netns | grep "${NETNS}"; then
		ip netns del ${NETNS}
	fi
	if invalid_dev "${HOSTDEV}" || invalid_dev "${NETNSDEV}"; then
		echo "Cannot find interfaces ${HOSTDEV} and ${NETNSDEV}" >&2
		exit 1
	fi
	if ! which ${TARGET} 2>&1 >/dev/null ; then
		echo "Cannot locate ${TARGET}" >&2
		exit 1
	fi
}

main()
{
	validate_args "$@"
	configure_netns
	while true; do
		if ! netns_exists || ! run_target; then
			break
		fi
	done
}

trap cleanup SIGINT SIGKILL
main "$@"
