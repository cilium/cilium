#!/bin/bash

source "./helpers.bash"

function cleanup {
	cilium policy delete --all 2> /dev/null || true
	docker rm -f server client 2> /dev/null || true
}

trap cleanup EXIT

TEST_NET="cilium"
SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

cleanup
logs_clear

function proxy_init {
	docker network inspect $TEST_NET 2> /dev/null || {
		docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
	}


	docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL cilium/demo-httpd
	docker run -dt --net=cilium --name client -l id.client tgraf/netperf


	SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
	SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
	SERVER_ID=$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')

	echo -n "Sleeping 3 seconds..."
	sleep 3
	echo " done."
	set -x

	cilium endpoint list

	cilium policy delete --all
	cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}}
	]
    }]
},{
    "endpointSelector": {"matchLabels":{"id.client":""}},
    "egress": [{
	"toPorts": [{
	    "ports": [{"port": "80", "protocol": "tcp"}],
	    "rules": {
                "HTTP": [{
		    "method": "GET",
		    "path": "/public"
                }]
	    }
	}]
    }]
}]
EOF
}


function proxy_test {
until [ "$(cilium endpoint list | grep cilium -c)" -eq 3 ]; do
	    echo "Waiting for all endpoints to be ready"
	        sleep 4s
done

RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80/public")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "GET /public, unexpected return"
fi

RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://[$SERVER_IP]:80/public")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "GET /public, unexpected return"
fi

RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80/private")
if [[ "${RETURN//$'\n'}" != "403" ]]; then
	abort "GET /private, unexpected return"
fi

RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://[$SERVER_IP]:80/private")
if [[ "${RETURN//$'\n'}" != "403" ]]; then
	abort "GET /private, unexpected return"
fi
}

for state in "false" "true"; do
	echo "Testing with Conntrack=$state"
	cilium config ConntrackLocal=$state
	sleep 2
	proxy_init
	sleep 2
	proxy_test
	cilium policy delete --all 2> /dev/null || true
	docker rm -f server client 2> /dev/null || true
	sleep 2
done
