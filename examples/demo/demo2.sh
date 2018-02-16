#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="cilium"
CLIENT_LABEL="id.client"
SERVER_LABEL="id.server"

function cleanup {
	docker rm -f server client 2> /dev/null || true
}

trap cleanup EXIT

cilium policy delete --all 2> /dev/null && true

desc "Demo: Create network, attach container, import policy"
desc ""

docker network rm $NETWORK > /dev/null 2>&1

desc "Create network \"cilium\""
desc "This step is only required once, all containers can be attached to the same network,"
desc "thus creating a single flat network. Isolation can then be defined based on labels."
run "docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium $NETWORK"

desc "Policy enforcement is disabled by default, enable it."
desc "Policy enforcement is also enabled as soon as you load a policy into the daemon."
run "cilium config PolicyEnforcement=always"

desc "Start a container with label $SERVER_LABEL"
run "docker run -d --net cilium --name server -l $SERVER_LABEL tgraf/netperf"

desc "List local endpoints"
run "cilium endpoint list"

run "docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server"
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_ID=$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')

desc "Ping will still fail due to missing policy"
run "ping6 -c 2 $SERVER_IP"

desc "Import policy"
desc "The policy allows containers with label client to talk to containers with label server"
desc "It also allows the local node to reach containers with label server"
run "cat $(relative policy.json)"
run "cilium policy import $(relative policy.json)"

desc "Ping from local node to server container now succeeds"
run "ping6 -c 2 $SERVER_IP"

desc "Start another container with label $CLIENT_LABEL"
run "docker run -d --net cilium --name client -l $CLIENT_LABEL tgraf/netperf"
sleep 3

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')

desc "A client and server container are now running on the local node"
run "cilium endpoint list"

desc "The client container can reach the server container"
run "docker exec -ti client ping6 -c 4 $SERVER_IP"

desc "Show policy table of server container"
desc "The table maintains a packets/bytes counter for each allowed consumer"
run "sudo cilium bpf policy get $SERVER_ID"

desc "Policies are directional and stateful, allowing client->server does not"
desc "automatically allow the reverse direction server->client. Only reply"
desc "packets are permitted. Ping will fail."
run "docker exec -ti server ping6 -c 4 $CLIENT_IP"

desc "Disabling connection tracking will disable directional policies and enable"
desc "automatic bidirectional policies. Compile out the connection tracking code"
desc "at runtime:"
run "cilium endpoint config $CLIENT_ID Conntrack=false"
run "cilium endpoint config $SERVER_ID Conntrack=false"

desc "Cilium has automatically allowed the server->client direction."
desc "Ping now succeeds in both directions"
run "docker exec -ti server ping6 -c 4 $CLIENT_IP"
run "docker exec -ti client ping6 -c 4 $SERVER_IP"

desc "Clean up"
run "docker rm -f server client"
