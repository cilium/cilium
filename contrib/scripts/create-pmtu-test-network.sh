#!/usr/bin/env bash

# Used for running pmtu tests in cilium-cli. Provides a simple
# test network setup on host, outside of a kind cluster (i.e.
# such as on LVH in CI) that is constrained by a non standard 
# MTU.
#
# Traffic intended for peer endpoint IPs with a pmtu exceeding
# the path network limit will have the kernel network stack
# respond with a ICMPv6: pkt-too-big or ICMP: frag-needed.
#
# Inside the test cluster this can be used to test Pod -> External
# Endpoint PMTU handling, specifically in the cases of bpf masquerade.
#
# Default endpoints:
# * ip4: 10.0.0.1
# * ip6: 2112:db8::2

VETH_ENDPOINT_IP6="2112:db8::1/64"
PEER_ENDPOINT_IP6="2112:db8::2/64"
VETH_ENDPOINT_IP4="10.0.0.0/28"
PEER_ENDPOINT_IP4="10.0.0.1/28"

TEST_NETNS=cilium_test

VETH_LINK_NAME=cilium_test0
PEER_LINK_NAME=cilium_test1

NETWORK_MTU=1400

set -euo pipefail

ip netns add ${TEST_NETNS}
ip link add ${VETH_LINK_NAME} type veth peer name ${PEER_LINK_NAME}
ip link set ${PEER_LINK_NAME} netns ${TEST_NETNS}
ip addr add ${VETH_ENDPOINT_IP6} dev ${VETH_LINK_NAME}
ip addr add ${VETH_ENDPOINT_IP4} dev ${VETH_LINK_NAME}
ip link set ${VETH_LINK_NAME} mtu ${NETWORK_MTU}
ip link set ${VETH_LINK_NAME} up
ip netns exec ${TEST_NETNS} ip addr add ${PEER_ENDPOINT_IP6} dev ${PEER_LINK_NAME}
ip netns exec ${TEST_NETNS} ip addr add ${PEER_ENDPOINT_IP4} dev ${PEER_LINK_NAME}
ip netns exec ${TEST_NETNS} ip link set ${PEER_LINK_NAME} up
ip netns exec ${TEST_NETNS} ip link set lo up
