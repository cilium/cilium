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
docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium $NETWORK > /dev/null
cilium policy delete io.cilium

desc "Import policy a policy"
desc "Allow all containers with label io.cilium.team1 to talk to each other."
run "cat $(relative demo4-policy.json)"
run "cilium policy import $(relative demo4-policy.json)"

desc "Start container with label team1"
run "docker run -d --net cilium --name demo4-team1 -l $TEAM1_LABEL noironetworks/netperf"

desc "Start container with label team2"
run "docker run -d --net cilium --name demo4-team2 -l $TEAM2_LABEL noironetworks/netperf"
sleep 2

TEAM2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' demo4-team2)
desc "Ping between team1 and team2 doesn't work because of policy:"
run "docker exec -ti demo4-team1 ping6 -c 2 $TEAM2_IP"

TEAM2_LABEL_ID=$(cilium endpoint list | grep $TEAM2_LABEL | awk '{ print $1}')
desc "Examine labels of team2 container:"
run "cilium endpoint labels $TEAM2_LABEL_ID"

desc "Enable LearnTraffic functionality for team2 container"
run "cilium endpoint config $TEAM2_LABEL_ID LearnTraffic=true"

desc "Ping still doesn't work but we are now learning based on incoming packets"
run "docker exec -ti demo4-team1 ping6 -c 2 $TEAM2_IP"

desc "Disable the LearnTraffic functionality again"
run "cilium endpoint config $TEAM2_LABEL_ID LearnTraffic=false"

desc "Examine labels of team 2 continer again"
desc "It was automatically learned that in order to consume team1, the label team1 is required"
run "cilium endpoint labels $TEAM2_LABEL_ID"

desc "Enable the newly learned label to allow traffic to flow"
run "cilium endpoint labels $TEAM2_LABEL_ID -e $TEAM1_LABEL"

desc "Ping works from Team 1 to Team 2"
run "docker exec -ti demo4-team1 ping6 -c 2 $TEAM2_IP"

desc "Clean up"
run "docker rm -f demo4-team1 demo4-team2"
