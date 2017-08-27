#!/bin/bash

source "./helpers.bash"

function cleanup {
	gather_files 10-proxy ${TEST_SUITE}
	cilium service delete --all
	cilium policy delete --all 2> /dev/null || true
	docker rm -f server1 server2 client 2> /dev/null || true
}

trap cleanup EXIT

TEST_NET="cilium"
SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

SVC_IP="f00d::1:1"
SVC_IP4="2.2.2.2"

cleanup
logs_clear

function service_init {
	cilium service update --rev --frontend "$SVC_IP4:80" --id 2233 \
			--backends "$SERVER1_IP4:80" \
			--backends "$SERVER2_IP4:80"

	cilium service update --rev --frontend "[$SVC_IP]:80" --id 2234 \
			--backends "[$SERVER1_IP]:80" \
			--backends "[$SERVER2_IP]:80"

	SERVER_IP=$SVC_IP
	SERVER_IP4=$SVC_IP4
}

function proxy_init {
	docker network inspect $TEST_NET 2> /dev/null || {
		docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
	}


	docker run -dt --net=$TEST_NET --name server1 -l $SERVER_LABEL cilium/demo-httpd
	docker run -dt --net=$TEST_NET --name server2 -l $SERVER_LABEL cilium/demo-httpd
	docker run -dt --net=cilium --name client -l id.client tgraf/netperf


	SERVER1_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server1)
	SERVER2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server2)
	SERVER1_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server1)
	SERVER2_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server2)

	SERVER_IP=$SERVER1_IP;
	SERVER_IP4=$SERVER1_IP4;

	wait_for_docker_ipv6_addr server1
	wait_for_docker_ipv6_addr server2
	wait_for_docker_ipv6_addr client

	set -x

    wait_for_cilium_ep_gen
	cilium endpoint list
}

function policy_single_egress {
	cilium policy delete --all
	cat <<EOF | policy_import_and_wait -
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
	cat <<EOF | policy_import_and_wait -
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
	cat <<EOF | policy_import_and_wait -
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
	cat <<EOF | policy_import_and_wait -
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

function policy_service_and_proxy_egress {
	cilium policy delete --all
	cat <<EOF | policy_import_and_wait -
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
	wait_for_endpoints 3

RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80/public")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "GET /public, unexpected return ${RETURN//$'\n'} != 200"
fi

RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://[$SERVER_IP]:80/public")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "GET /public, unexpected return ${RETURN//$'\n'} != 200"
fi

RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80/private")
if [[ "${RETURN//$'\n'}" != "403" ]]; then
	abort "GET /private, unexpected return ${RETURN//$'\n'} != 403"
fi

RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://[$SERVER_IP]:80/private")
if [[ "${RETURN//$'\n'}" != "403" ]]; then
	abort "GET /private, unexpected return ${RETURN//$'\n'} != 403"
fi
}

for service in "none" "lb"; do
	for policy in "egress" "ingress" "many_egress" "many_ingress"; do
		# FIXME GH-1404 Convert to endpoint specific local conntrack setting
		#for state in "false" "true"; do
		for state in "false"; do
			echo "Testing with Policy=$policy, Conntrack=$state, Service=$service"
			#cilium config ConntrackLocal=$state
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


			case $service in
				"none")
					;;
				"lb")
					service_init;;
			esac

	        wait_for_cilium_ep_gen
		wait_for_policy_enforcement
			cilium endpoint list
			proxy_test
			cilium service delete --all
			cilium policy delete --all 2> /dev/null || true
			docker rm -f server1 server2 client 2> /dev/null || true
			wait_for_cilium_ep_gen
		done
	done
done
