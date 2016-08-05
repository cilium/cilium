#!/bin/bash

set -e

function node_run {
	NODE=$1
	shift

	vagrant ssh $NODE -- -t "$*"
}

function cleanup {
	node_run node1 'docker rm -f server 2> /dev/null' || true
	node_run node2 'docker rm -f client 2> /dev/null' || true
}

trap cleanup EXIT

function init {
	vagrant up node1
	vagrant up node2

	cleanup

	node_run node1 'docker network create --driver cilium --ipam-driver cilium cilium 2> /dev/null' || true
	node_run node2 'docker network create --driver cilium --ipam-driver cilium cilium 2> /dev/null' || true
}

function test_run {
	SERVER=$(node_run node1 'docker run -d --net cilium -l io.cilium.server --name server noironetworks/netperf')
	CLIENT=$(node_run node2 'docker run -d --net cilium -l io.cilium.client --name client noironetworks/netperf')
	sleep 5s

	SERVER_IP=$(node_run node1 "docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server" | tr -d '\r')
	echo "Server IPv6: $SERVER_IP"

	node_run node2 "docker exec -i client ping6 -c 5 $SERVER_IP"
	node_run node2 "docker exec -i client netperf -t TCP_STREAM -H $SERVER_IP"

	SERVER_IP4=$(node_run node1 "docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server" | tr -d '\r')
	echo "Server IPv4: $SERVER_IP4"
	node_run node2 "docker exec -i client ping -c 5 $SERVER_IP4"
	node_run node2 "docker exec -i client netperf -t TCP_STREAM -H $SERVER_IP4"

	cleanup
}

function test_nodes {
	OPTS=$*

	echo "Setting up nodes with options: $OPTS"

	node_run node1 "cp /etc/init/cilium-net-daemon.conf tmp; sed -i '/exec/d' tmp; echo \"exec cilium -D daemon run -n f00d::c0a8:210b:0 --ipv4-range 10.1.0.1 $OPTS\" >> tmp; sudo cp tmp /etc/init/cilium-net-daemon.conf; sudo service cilium-net-daemon restart"
	node_run node2 "cp /etc/init/cilium-net-daemon.conf tmp; sed -i '/exec/d' tmp; echo \"exec cilium -D daemon run -n f00d::c0a8:210c:0 --ipv4-range 10.2.0.1 $OPTS -c 192.168.33.11:8500\" >> tmp; sudo cp tmp /etc/init/cilium-net-daemon.conf; sudo service cilium-net-daemon restart"

	echo "Waiting for daemon to start up..."
	sleep 5s

	node_run node1 'cilium policy import ~/go/src/github.com/noironetworks/cilium-net/examples/policy/default/'
	node_run node2 'cilium policy import ~/go/src/github.com/noironetworks/cilium-net/examples/policy/default/'

	test_run
}

init
test_nodes "-t vxlan --ipv4"
test_nodes "-d eth1"
