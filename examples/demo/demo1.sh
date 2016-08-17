#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="cilium"
CLIENT_LABEL="io.cilium.client"

function cleanup {
	docker rm -f demo1 2> /dev/null || true
}

trap cleanup EXIT

docker network rm $NETWORK > /dev/null 2>&1

desc "Create network \"cilium\""
run "docker network create --driver cilium --ipam-driver cilium $NETWORK"

desc "Start a container"
run "docker run -d --net cilium --name demo1 -l $CLIENT_LABEL noironetworks/netperf"

desc "Examine network configuration of container"
run "docker exec -ti demo1 ip -6 a"
run "docker exec -ti demo1 ip -6 r"

desc "Examine cilium state"
run "cilium endpoint list"

desc "Clean up"
run "docker rm -f demo1"
