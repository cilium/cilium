#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="cilium"
CLIENT_LABEL="client"

function cleanup {
	docker rm -f demo1 2> /dev/null || true
}

trap cleanup EXIT

docker network rm $NETWORK > /dev/null 2>&1

desc "Demo: Start a container and examine network configuration"
desc ""
desc "Create network \"cilium\""
desc "This step is only required once, all containers can be attached to the same network,"
desc "thus creating a single flat network. Isolation can then be defined based on labels."
run "docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium $NETWORK"

desc "Start a container"
run "docker run -d --net cilium --name demo1 -l $CLIENT_LABEL tgraf/netperf"

desc "Examine network configuration of container"
desc "The container was allocated a unique IPv6 address from the node prefix"
run "docker exec -ti demo1 ip -6 address list"

desc "All traffic uses a single default route pointing to the node's address"
run "docker exec -ti demo1 ip -6 route list dev cilium0"

desc "Examine list of local cilium endpoints"
run "cilium endpoint list"

desc "Clean up"
run "docker rm -f demo1"
