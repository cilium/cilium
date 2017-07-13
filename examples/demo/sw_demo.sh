#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="space"
PWD=$(dirname ${BASH_SOURCE})

function cleanup {
	tmux kill-session -t my-session >/dev/null 2>&1
	docker rm -f deathstar luke xwing_luke xwing fighter1 2> /dev/null || true
	cilium policy delete --all 2> /dev/null
}

trap cleanup EXIT
cleanup

sleep 0.5
desc_rate "A long time ago, in a container cluster far, far away...."
desc_rate ""
desc_rate "It is a period of civil war. The Empire has adopted"
desc_rate "microservices and continuous delivery, despite this,"
desc_rate "Rebel spaceships, striking from a hidden cluster, have"
desc_rate "won their first victory against the evil Galactic Empire."
desc_rate ""
desc_rate "During the battle, Rebel spies managed to steal the"
desc_rate "swagger API specification to the Empire's ultimate weapon,"
desc_rate "the deathstar."
run ""

docker network rm $NETWORK > /dev/null 2>&1
desc_rate "And so it begins..."
run "docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium $NETWORK"

desc_rate "The empire begins constructing the death star by launching a container"
run "docker run -dt --net=$NETWORK --name deathstar -l id.empire.deathstar cilium/starwars"

desc_rate "In order for spaceships to land, the empire establishes"
desc_rate "a network landing policy (L3/L4). It allows id.spaceship"
desc_rate "to talk to id.deathstar."
run "cat sw_policy_l4.json"
run "cilium policy import sw_policy_l4.json"

DEATHSTAR_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.space.IPAddress }}' deathstar)

desc_rate "The empire wants to test landing permissions..."
run "docker run -dt --net=$NETWORK --name fighter1 -l id.spaceship --add-host deathstar:$DEATHSTAR_IP4 tgraf/netperf"
run "cilium endpoint list"

desc "The spaceship issues a POST /v1/request-landing to the deathstar"
run "docker exec -i fighter1 curl -si -XPOST http://deathstar/v1/request-landing"

desc_rate "Spaceship has landed \o/. The empire celebrates."
run ""
desc_rate "In the meantime...."
desc_rate ""
desc_rate "The rebel alliance notices the construction of the death star"
desc_rate "and sends a scout."
run "docker run -dt --net=$NETWORK --name xwing -l id.spaceship --add-host deathstar:$DEATHSTAR_IP4 tgraf/netperf"
desc_rate "It pings the the deathstar (L3 policy) ..."
run "docker exec -i xwing ping -c 2 deathstar"
desc_rate "... and then sends a GET /v1/ to the deathstar (L4 policy)"
run "docker exec -i xwing curl -si -XGET http://deathstar/v1/"
desc_rate "Wow..... the deathstar exposes the entire API..."
desc_rate "Look at that thermal exhaust port, it seems vulnerable..."
run ""
desc_rate "In the meantime...."
desc_rate "The SecOps team of the empire has detected the security"
desc_rate "hole and deploys cilium HTTP policies:"
run "cat sw_policy_http.json"
run "cilium policy import sw_policy_http.real.json"

desc_rate ""
desc_rate "The rebels attack... they first ping ...."
run "docker exec -i xwing ping -c 2 deathstar"
desc_rate "... and will now attack the vulnerable API endpoint"
desc_rate "by doing: curl -si -XPUT http://deathstar/v1/exhaust-port"
run ""
run "docker exec -i xwing curl -si -XPUT http://deathstar/v1/exhaust-port"

desc_rate "Oh no! The shields are up. The rebel attack is ineffective".
desc_rate ""
desc_rate "End of demo."
run ""

desc_rate "The move of Empire SecOps was good but we can't end the"
desc_rate "story like this."
desc_rate ""
desc_rate "Here is what you missed..."
desc_rate ""
desc_rate "The Jedi have foreseen this situation and manipulated the"

desc_rate "L7 policy before it was installed."
desc_rate ""
desc_rate "Let's run diff on the policy that was actually loaded..."
run "diff -Nru sw_policy_http.json sw_policy_http.real.json"

desc_rate "The policy allows an HTTP request to pass through if the"
desc_rate "HTTP header 'X-Has-Force: true' is set"
run ""
run "docker run -dt --net=$NETWORK --name xwing_luke -l id.spaceship --add-host deathstar:$DEATHSTAR_IP4 tgraf/netperf"
run ""
run "docker exec -i xwing_luke curl -si -H 'X-Has-Force: true' -XPUT http://deathstar/v1/exhaust-port/"

desc_rate "Luke watches the deathstar explode..."
run "docker exec -i xwing_luke ping deathstar"

#tmux new -d -s my-session \
#    "$PWD/starwars_top.sh" \; \
#    split-window -v -d "$PWD/starwars_bottom.sh" \; \
#    attach \;

desc "Cleaning up demo environment"
