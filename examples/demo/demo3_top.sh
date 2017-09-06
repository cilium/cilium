#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

CLIENT_LABEL="id.client"
SERVER_LABEL="id.server"

SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)

run ""

desc "Ping again to trigger events"
run "docker exec -ti client ping6 -c 4 $SERVER_IP"

desc "Not enough information? Enable debug mode!"
desc "This will recompile the BPF programs with debug instructions while the containers keeps running"
run "cilium endpoint list"

SERVER_ID=$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')
run "cilium endpoint config $CLIENT_ID Debug=true"
run "cilium endpoint config $SERVER_ID Debug=true"

desc "Ping again to see debugging events"
run "docker exec -ti client ping6 -c 4 $SERVER_IP"

clear
desc "Packets get dropped due to policy denial. Trace the policy decision"
run "cilium policy trace -s $CLIENT_LABEL -d $SERVER_LABEL"

desc "No policy has been loaded, import it."
run "cat $(relative policy.json)"
run "cilium policy import $(relative policy.json)"

clear
desc "Trace policy again"
run "cilium policy trace -s $CLIENT_LABEL -d $SERVER_LABEL"

desc "Ping should now work as expected"
run "docker exec -ti client ping6 -c 4 $SERVER_IP"

desc "All good. Compile out debug and drop notifications again for efficiency"

run "cilium endpoint config $CLIENT_ID Debug=false DropNotification=false TraceNotification=false"
run "cilium endpoint config $SERVER_ID Debug=false DropNotification=false TraceNotification=false"

desc "Ping will no longer trigger events for these containers"
run "docker exec -ti client ping6 -c 4 $SERVER_IP"
