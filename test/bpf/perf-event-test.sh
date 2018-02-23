#!/bin/bash

set -e

TESTDEV=perf_test
TESTDEV1=$TESTDEV
TESTDEV2=${TESTDEV}_peer

ADDR1="10.254.254.253"
ADDR2="10.254.254.254"

function cleanup
{
	ip addr del $ADDR1/24 dev $TESTDEV1 2> /dev/null || true
	ip link del $TESTDEV1 2> /dev/null || true
	ip netns exec $TESTDEV2 ip addr del $ADDR2/24 dev $TESTDEV2 2> /dev/null || true
	ip netns del $TESTDEV2 2> /dev/null || true
}

function setup
{
	ip netns add $TESTDEV2

	ip link add $TESTDEV1 type veth peer name $TESTDEV2
	ip link set $TESTDEV2 netns $TESTDEV2
	ip link set $TESTDEV1 up
	ip addr add $ADDR1/24 dev $TESTDEV1

	ip netns exec $TESTDEV2 ip link set $TESTDEV2 up
	ip netns exec $TESTDEV2 ip addr add $ADDR2/24 dev $TESTDEV2

	tc qdisc replace dev $TESTDEV1 clsact
	tc filter add dev $TESTDEV1 ingress bpf da obj $1
}

function main
{
	if [ $# -lt 1 ]; then
		echo "usage: $0 <bpf-object-file>"
		exit 1
	fi

	cleanup
	trap cleanup EXIT
	setup "$@"

	ping -c 10 $ADDR2&
	timeout 10 ./perf-event-test || true
}

main "$@"
