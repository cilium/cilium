#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="cilium"
CLIENT_LABEL="id.client"
SERVER_LABEL="id.server"

function cleanup {
	tmux kill-session -t my-session >/dev/null 2>&1
	docker rm -f client server 2> /dev/null || true
}

trap cleanup EXIT

docker network rm $NETWORK > /dev/null 2>&1
docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium $NETWORK > /dev/null
cilium policy delete --all

desc "Policy enforcement is disabled by default, enable it."
run "cilium config PolicyEnforcement=always"

desc "How to debug a connectivity issue?"
desc "Start client and server containers"
run "docker run -d --net cilium --name server -l $SERVER_LABEL tgraf/netperf"
run "docker run -d --net cilium --name client -l $CLIENT_LABEL tgraf/netperf"
sleep 2

SERVER_ID=$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')
cilium endpoint config $CLIENT_ID debug=false
cilium endpoint config $SERVER_ID debug=false

run "cilium endpoint list"

SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
desc "Situation: Ping doesn't work, now what?"
run "docker exec -ti client ping6 -c 2 $SERVER_IP"

tmux new -d -s my-session \
    "$(dirname ${BASH_SOURCE})/demo3_top.sh" \; \
    split-window -v -d "$(dirname $BASH_SOURCE)/demo3_bottom.sh" \; \
    attach \;

desc "Clean up"
run "docker rm -f server client"
