#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="cilium"
CLIENT_LABEL="io.cilium.client"
SERVER_LABEL="io.cilium.server"

function cleanup {
	docker rm -f server client 2> /dev/null || true
}

trap cleanup EXIT

desc "Demo: Create network, attach container, import policy"

docker network rm $NETWORK > /dev/null 2>&1

desc "Create network \"cilium\""
run "docker network create --driver cilium --ipam-driver cilium $NETWORK"

cilium policy delete io.cilium

desc "Start a container with label $SERVER_LABEL"
run "docker run -d --net cilium --name server -l $SERVER_LABEL noironetworks/netperf"
sleep 2

desc "List local endpoints"
run "cilium endpoint list"

run "docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server"
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_ID=$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')

desc "Ping will still fail due to missing policy"
run "ping6 -c 2 $SERVER_IP"

desc "Import policy"
run "cat $(relative policy.json)"
run "cilium policy import $(relative policy.json)"

desc "Ping now succeeds"
run "ping6 -c 2 $SERVER_IP"

desc "Start another container with label $CLIENT_LABEL"
run "docker run -d --net cilium --name client -l $CLIENT_LABEL noironetworks/netperf"
sleep 2

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')

run "cilium endpoint list"

desc "The client container can reach the server container"
run "docker exec -ti client ping6 -c 4 $SERVER_IP"

desc "Show policy table of server container"
run "sudo cilium endpoint policy dump $SERVER_ID"

desc "Policies are directional, even though client->server is allowed, the"
desc "reverse direction is not automatically allowed."
run "docker exec -ti server ping6 -c 4 $CLIENT_IP"

desc "Disabling connection tracking enables automatic bidirectional policies"
desc "because we no longer track replies"
run "cilium endpoint config $CLIENT_ID Conntrack=false"
run "cilium endpoint config $SERVER_ID Conntrack=false"

desc "Ping now succeeds in both directions"
run "docker exec -ti server ping6 -c 4 $CLIENT_IP"
run "docker exec -ti client ping6 -c 4 $SERVER_IP"

desc "Clean up"
run "docker rm -f server client"
