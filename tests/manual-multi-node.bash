#!/usr/bin/env bash

source "./helpers.bash"

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )


set -e

export NWORKERS=1

function node_run {
	NODE=$1
	shift

	echo "Running on ${NODE}: $*"
	vagrant ssh $NODE -- -t "$*"
}

function node_run_quiet {
	NODE=$1
	shift

	vagrant ssh $NODE -- -t "$*"
}

function cleanup {
	node_run cilium-master 'docker rm -f server 2> /dev/null' || true
	node_run cilium-node-2 'docker rm -f client 2> /dev/null' || true
}

trap cleanup EXIT

function init {
    "${dir}/../contrib/vagrant/start.sh"

	cleanup

	node_run cilium-master 'docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium cilium 2> /dev/null' || true
	node_run cilium-node-2 'docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium cilium 2> /dev/null' || true
}

function test_run {
	SERVER=$(node_run_quiet cilium-master 'docker run -d --net cilium -l id.server --name server tgraf/netperf')
	CLIENT=$(node_run_quiet cilium-node-2 'docker run -d --net cilium -l id.client --name client tgraf/netperf')

	SERVER_IP=$(node_run_quiet cilium-master "docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server" | tr -d '\r')
	echo "Server IPv6: $SERVER_IP"

	node_run cilium-node-2 "docker exec -i client ping6 -c 5 $SERVER_IP"
	node_run cilium-node-2 "docker exec -i client netperf -t TCP_STREAM -H $SERVER_IP"

	if [ ! -z "$IPV4" ]; then
		SERVER_IP4=$(node_run_quiet cilium-master "docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server" | tr -d '\r')
		echo "Server IPv4: $SERVER_IP4"
		node_run cilium-node-2 "docker exec -i client ping -c 5 $SERVER_IP4"
		node_run cilium-node-2 "docker exec -i client netperf -t TCP_STREAM -H $SERVER_IP4"
	fi

	cleanup
}

function test_nodes {
	OPTS=$*

	echo "------------------------------------------------------------------------"
	echo "Setting up nodes with options: $OPTS"
	echo "------------------------------------------------------------------------"

	node_run cilium-master "sudo cp /etc/init/cilium.conf tmp; sudo sed -i '/exec/d' tmp; echo \"exec cilium-agent --debug -n f00d::c0a8:210b:0:0 --ipv4-range 10.1.0.0/16 $OPTS\" | sudo tee -a tmp; sudo cp tmp /etc/init/cilium.conf; sudo service cilium restart"
	node_run cilium-node-2 "sudo cp /etc/init/cilium.conf tmp; sudo sed -i '/exec/d' tmp; echo \"exec cilium-agent --debug -n f00d::c0a8:210c:0:0 --ipv4-range 10.2.0.0/16 $OPTS -c 192.168.33.11:8500\" | sudo tee -a tmp; sudo cp tmp /etc/init/cilium.conf; sudo service cilium restart"

	echo "Waiting for daemon to start up..."
	wait_for_cilium_status

	node_run cilium-master 'cilium policy import ~/go/src/github.com/cilium/cilium/examples/policy/default/'
	node_run cilium-node-2 'cilium policy import ~/go/src/github.com/cilium/cilium/examples/policy/default/'

	test_run
}

init
IPV4=1 test_nodes "-t vxlan"
test_nodes "-d eth1"
