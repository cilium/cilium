#!/bin/bash

source "./helpers.bash"

function cleanup {
	docker rm -f server client 2> /dev/null || true
}

trap cleanup EXIT

TEST_NET="cilium"
SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

cleanup
logs_clear

docker network inspect $TEST_NET 2> /dev/null || {
	docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL httpd
docker run -dt --net=$TEST_NET --name client -l $CLIENT_LABEL tgraf/netperf

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
SERVER_ID=$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')

echo -n "Sleeping 3 seconds..."
sleep 3
echo " done."
set -x

cilium endpoint list

cat <<EOF | cilium -D policy import -
{
        "name": "root",
	"rules": [{
		"coverage": ["id.client"],
		"l4": [{
			"out-ports": [{
				"port": 80, "protocol": "tcp",
				"l7-parser": "http",
				"l7-rules": [{ "expr": "Method(\"GET\") && Path(\"/public\")" }]
			}]
		}]
	},{
		"coverage": ["id.server"],
		"allow": ["id.client", "reserved:host"]
	}]
}
EOF

sleep 2

RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80/public")
if [[ "${RETURN//$'\n'}" != "404" ]]; then
	abort "GET /public, unexpected return"
fi


RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80/private")
if [[ "${RETURN//$'\n'}" != "403" ]]; then
	abort "GET /private, unexpected return"
fi

cilium policy delete root
