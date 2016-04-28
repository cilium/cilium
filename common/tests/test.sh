#!/bin/bash

set -e

TESTDEV=perf_test
TESTDEV1=$TESTDEV
TESTDEV2=${TESTDEV}_peer

ADDR1="10.254.254.253"
ADDR2="10.254.254.254"

ip netns del $TESTDEV2 2> /dev/null || true
ip netns add $TESTDEV2

ip link del $TESTDEV1 2> /dev/null || true
ip link add $TESTDEV1 type veth peer name $TESTDEV2
ip link set $TESTDEV2 netns $TESTDEV2

ip link set $TESTDEV1 up
ip addr del $ADDR1/24 dev $TESTDEV1 2> /dev/null || true
ip addr add $ADDR1/24 dev $TESTDEV1

ip netns exec $TESTDEV2 ip link set $TESTDEV2 up
ip netns exec $TESTDEV2 ip addr del $ADDR2/24 dev $TESTDEV2 2> /dev/null || true
ip netns exec $TESTDEV2 ip addr add $ADDR2/24 dev $TESTDEV2

tc qdisc del dev $TESTDEV1 clsact 2> /dev/null || true
tc qdisc add dev $TESTDEV1 clsact
tc filter add dev $TESTDEV1 ingress bpf da obj $1

ping -c 10 $ADDR2&

timeout 10 ./perf-event-test || true
