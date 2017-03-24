#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="space"

desc "Make X-Wing put something into the thermal exhaust port"
run "docker exec -i xwing curl -si -XPUT http://$DEATHSTAR_IP4:80/v1/exhaustport"

run "cat l7_demo_policy_http.json"
run "cilium policy delete root"
run "cilium policy import l7_demo_policy_http.json"

desc "Put something into the thermal exhaust port again"
run "docker exec -i xwing curl -si -XPUT http://$DEATHSTAR_IP4:80/v1/exhaustport"

desc "Query information from deathstar still works"
run "docker exec -i xwing curl -si -XGET http://$DEATHSTAR_IP4:80/v1/"

desc "Use the force, Luke ...."
run "docker run -dt --net=$NETWORK --name luke -l jedi.force -l rebel.luke tgraf/netperf"
run "docker exec -i luke curl -si -XPUT http://$DEATHSTAR_IP4:80/v1/exhaustport"

cilium -D policy delete root
