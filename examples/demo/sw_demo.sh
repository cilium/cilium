#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="space"
PWD=$(dirname ${BASH_SOURCE})

function cleanup {
	tmux kill-session -t my-session >/dev/null 2>&1
	docker rm -f deathstar luke xwing_luke xwing fighter1 2> /dev/null || true
	cilium policy delete root 2> /dev/null
}

trap cleanup EXIT
cleanup

sleep 0.5
desc_rate "A long time ago, in a container cluster far, far away...."
desc_rate "It is a period of civil war. The Empire has adopted"
desc_rate "microservices and continuous delivery, despite this,"
desc_rate "Rebel spaceships, striking from a hidden base, have"
desc_rate "won their first victory against the evil Galactic Empire."
desc_rate "During the battle, Rebel spies managed to steal the"
desc_rate "swagger API specification to the Empire's ultimate weapon,"
desc_rate "the DEATH STAR, an armored space station with enough power"
desc_rate "to destroy an entire planet."
run ""

docker network rm $NETWORK > /dev/null 2>&1
desc_rate "At the beginning of our story space itself was created..."
run "docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium $NETWORK"

desc_rate "The empire begins to construct a deathstar in space..."
run "docker run -dt --net=$NETWORK --name deathstar -l id.empire.deathstar tgraf/starwars"

desc_rate "In order for spaceships to land, the empire establishes"
desc_rate "an L3/L4 landing policy for spaceships."
run "cat sw_policy_l4.json"
run "cilium policy import sw_policy_l4.json"

DEATHSTAR_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.space.IPAddress }}' deathstar)

desc_rate "To test the landing policy, a spacefighter is launched..."
run "docker run -dt --net=$NETWORK --name fighter1 -l id.spaceship --add-host deathstar:$DEATHSTAR_IP4 tgraf/netperf"
run "cilium endpoint list"

desc "... and then lands by issuing a POST /v1/requestlanding"
run "docker exec -i fighter1 curl -si -XPOST http://deathstar/v1/requestlanding"

desc_rate "The empire celebrates the success of installing an L3/L4"
desc_rate "policy but this does not go unnoticed by the rebel alliance"
desc_rate "which is aware of its weaknesses."
desc_rate "They send a T-70 X-wing fighter to scout the deathstar APIs"
run "docker run -dt --net=$NETWORK --name xwing -l id.spaceship --add-host deathstar:$DEATHSTAR_IP4 tgraf/netperf"
desc_rate "... it sends a ping and a GET /v1/ probe to the deathstar"
run "docker exec -i xwing ping -c 2 deathstar"
run "docker exec -i xwing curl -si -XGET http://deathstar/v1/"
desc_rate "The rebels notice that the deathstar has vulnerable HTTP"
desc_rate "API endpoints, in particular they notice the possibility"
desc_rate "to access the PUT /v1/exhaustport API endpoint"
run ""
desc_rate "In the meantime, the SecOps team of the empire have detected"
desc_rate "the security hole and deployed cilium to put a HTTP level"
desc_rate "policy in place:"
run "cat sw_policy_http.json"
run "cilium policy delete root"
run "cilium policy import sw_policy_http.real.json"

desc_rate "The rebels attack, they can see the deathstar:"
run "docker exec -i xwing ping -c 2 deathstar"
desc_rate "But as they attack the vulnerable API endpoint:"
run "docker exec -i xwing curl -si -XPUT http://deathstar/v1/exhaustport"

desc_rate "Oh no! The shields are up. The rebel attack is ineffective".
desc_rate "End of demo?"
run ""
desc_rate "Despite the obvious good move of the Empire SecOps team to"
desc_rate "adopt cilium and HTTP security policies, we can't let the"
desc_rate "empire win so here is what really happened..."

desc_rate "The Jedi have foreseen this situation and manipulated the"
desc_rate "L7 policy before it was installed:"

run "diff -Nru sw_policy_http.json sw_policy_http.real.json"

desc_rate "The policy allows an HTTP request to pass through if the"
desc_rate "HTTP header X-Has-Force: true is set in the request"
run "docker run -dt --net=$NETWORK --name xwing_luke -l id.spaceship --add-host deathstar:$DEATHSTAR_IP4 tgraf/netperf"
run "docker exec -i xwing_luke curl -si -H 'X-Has-Force: true' -XPUT http://deathstar/v1/exhaustport"

desc_rate "Everything is back in order, the deathstar is gone ..."
run "docker exec -i xwing_luke ping deathstar"

#tmux new -d -s my-session \
#    "$PWD/starwars_top.sh" \; \
#    split-window -v -d "$PWD/starwars_bottom.sh" \; \
#    attach \;

desc "Cleaning up demo environment"
