#!/bin/bash

set -e

function node_run {
	NODE=$1
	shift

	vagrant ssh $NODE -- -t "$*"
}

vagrant up node1
vagrant up node2

node_run node1 'docker rm -f server 2> /dev/null' || true
node_run node2 'docker rm -f client 2> /dev/null' || true

SERVER=$(node_run node1 'docker run -d --net cilium -l io.cilium.server --name server noironetworks/netperf')
CLIENT=$(node_run node2 'docker run -d --net cilium -l io.cilium.client --name client noironetworks/netperf')
sleep 5s

SERVER_IP=$(node_run node1 "docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server" | tr -d '\r')
echo "Server IPv6: $SERVER_IP"

node_run node2 "docker exec -i client ping6 -c 5 $SERVER_IP"

SERVER_IP4=$(node_run node1 "docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server" | tr -d '\r')
echo "Server IPv4: $SERVER_IP4"
node_run node2 "docker exec -i client ping -c 5 $SERVER_IP4"

node_run node1 'docker rm -f server'
node_run node2 'docker rm -f client'
