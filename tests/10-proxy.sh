#!/bin/bash

source "./helpers.bash"

function cleanup {
	gather_files 10-proxy
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

	wait_for_docker_ipv6_addr server
	wait_for_docker_ipv6_addr client

	set -x

    wait_for_cilium_ep_gen
	cilium endpoint list
}

function policy_single_egress {
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

function policy_many_egress {
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
	    "ports": [{"port": "8000", "protocol": "tcp"},
		      {"port": "80",   "protocol": "tcp"},
		      {"port": "8080", "protocol": "tcp"},
		      {"port": "8080", "protocol": "udp"}],
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

function policy_single_ingress {
	cilium policy delete --all
	cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}}
	],
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

function policy_many_ingress {
	cilium policy delete --all
	cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}}
	],
	"toPorts": [{
	    "ports": [{"port": "80", "protocol": "tcp"},
		      {"port": "8080", "protool": "tcp"},
		      {"port": "8080", "protocol": "udp"},
		      {"port": "8000", "protocol": "udp"}],
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
	wait_for_endpoints 2

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

for policy in "egress" "ingress" "many_egress" "many_ingress"; do
	for state in "false" "true"; do
		echo "Testing with Policy=$policy, Conntrack=$state"
		cilium config ConntrackLocal=$state
		wait_for_cilium_ep_gen
		proxy_init

		case $policy in
			"many_egress")
				policy_many_egress;;
			"egress")
				policy_single_egress;;
			"many_ingress")
				policy_many_ingress;;
			"ingress")
				policy_single_ingress;;
		esac

        wait_for_cilium_ep_gen
		proxy_test
		cilium policy delete --all 2> /dev/null || true
		docker rm -f server client 2> /dev/null || true
		wait_for_cilium_ep_gen
	done
done
