#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="cilium"
TEAM1_LABEL="io.cilium.team1"
TEAM2_LABEL="io.cilium.team2"

function cleanup {
	docker rm -f demo4-team1 demo4-team2 2> /dev/null || true
}

trap cleanup EXIT

docker network rm $NETWORK > /dev/null 2>&1

desc "Create network \"cilium\""
run "docker network create --driver cilium --ipam-driver cilium $NETWORK"

cilium policy delete io.cilium

desc "Import policy"
run "cat $(relative demo4-policy.json)"
run "cilium policy import $(relative demo4-policy.json)"

desc "Start container for team1"
run "docker run -d --net cilium --name demo4-team1 -l $TEAM1_LABEL noironetworks/netperf"

desc "Start container for team2"
run "docker run -d --net cilium --name demo4-team2 -l $TEAM2_LABEL noironetworks/netperf"
sleep 2

TEAM2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' demo4-team2)
desc "Situation: Ping doesn't work..."
run "docker exec -ti demo4-team1 ping6 -c 2 $TEAM2_IP"
desc "Because Team 1 can only speak with Team 1!"

TEAM2_LABEL_ID=$(cilium endpoint list | grep $TEAM2_LABEL | awk '{ print $1}')
desc "Current Team 2 labels"
run "cilium endpoint labels $TEAM2_LABEL_ID"

desc "Let's enable LearnTraffic functionality to learn labels from incoming traffic"
run "cilium endpoint config $TEAM2_LABEL_ID LearnTraffic=true"

desc "Ping still doesn't work but we are listening for incoming packets on Team 2"
run "docker exec -ti demo4-team1 ping6 -c 2 $TEAM2_IP"

desc "Examine Team 2 labels again"
run "cilium endpoint labels $TEAM2_LABEL_ID"

desc "We can disable the LearnTraffic functionality"
run "cilium endpoint config $TEAM2_LABEL_ID LearnTraffic=false"

desc "And enable the new learned Team 1 label"
run "cilium endpoint labels $TEAM2_LABEL_ID -e $TEAM1_LABEL"

desc "Ping works from Team 1 to Team 2"
run "docker exec -ti demo4-team1 ping6 -c 2 $TEAM2_IP"

desc "Clean up"
run "docker rm -f demo4-team1 demo4-team2"
