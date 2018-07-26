#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

log "${TEST_NAME} has been deprecated and replaced by test/runtime/lb.go:Services Policies"
exit 0

function cleanup {
  monitor_stop
  cilium service delete --all 2> /dev/null || true
  cilium policy delete --all 2> /dev/null || true
  docker rm -f server1 server2 client 2> /dev/null || true
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

trap finish_test EXIT

SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

SVC_IP="f00d::1:1"
SVC_IP4="2.2.2.2"

cleanup
logs_clear

function no_service_init {
  cilium service delete --all
  SERVER_IP=$SERVER1_IP;
  SERVER_IP4=$SERVER1_IP4;
}

function service_init {
  log "beginning service init"
  cilium service update --rev --frontend "$SVC_IP4:80" --id 2233 \
			--backends "$SERVER1_IP4:80" \
			--backends "$SERVER2_IP4:80"

  cilium service update --rev --frontend "[$SVC_IP]:80" --id 2234 \
			--backends "[$SERVER1_IP]:80" \
			--backends "[$SERVER2_IP]:80"

  SERVER_IP=$SVC_IP
  SERVER_IP4=$SVC_IP4
  log "finished service init"
}

function proxy_init {
  log "beginning proxy_init"
  create_cilium_docker_network

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

  log "waiting for all 4 endpoints to get an identity"
  while [ `cilium endpoint list -o jsonpath='{range [*]}{.status.identity.id}{"\n"}{end}' | grep '^[0-9]' | grep -v '^5$' | wc -l` -ne 4 ] ; do
    log "waiting..."
    sleep 1
  done

  monitor_start
  log "finished proxy_init"
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
		      {"port": "8080", "protocol": "tcp"}],
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
		      {"port": "8080", "protocol": "tcp"}],
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

function policy_egress_and_ingress {
  cilium policy delete --all
  cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
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
},{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
	"toPorts": [{
	    "ports": [{"port": "8000", "protocol": "tcp"},
		      {"port": "80",   "protocol": "tcp"},
		      {"port": "8080", "protocol": "tcp"}],
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
  log "beginning proxy test"
  monitor_clear

  log "trying to reach server IPv4 at http://$SERVER_IP4:80/public from client (expected: 200)"
  RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80/public")
  if [[ "${RETURN//$'\n'}" != "200" ]]; then
    abort "GET /public, unexpected return ${RETURN//$'\n'} != 200"
  fi

  log "trying to reach server IPv6 at http://[$SERVER_IP]:80/public from client (expected: 200)"
  RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://[$SERVER_IP]:80/public")
  if [[ "${RETURN//$'\n'}" != "200" ]]; then
    abort "GET /public, unexpected return ${RETURN//$'\n'} != 200"
  fi

  log "trying to reach server IPv4 at http://$SERVER_IP4:80/private from client (expected: 403)"
  RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80/private")
  if [[ "${RETURN//$'\n'}" != "403" ]]; then
    abort "GET /private, unexpected return ${RETURN//$'\n'} != 403"
  fi

  log "trying to reach server IPv6 at http://[$SERVER_IP]:80/private from client (expected: 403)"
  RETURN=$(docker exec -i client bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://[$SERVER_IP]:80/private")
  if [[ "${RETURN//$'\n'}" != "403" ]]; then
    abort "GET /private, unexpected return ${RETURN//$'\n'} != 403"
  fi

  log "finished proxy test"
}

proxy_init
for state in "false" "true"; do
  cilium config ConntrackLocal=$state

  for service in "none" "lb"; do
    case $service in
      "none")
        no_service_init;;
      "lb")
        service_init;;
    esac

    for policy in "egress" "ingress" "egress_and_ingress" "many_egress" "many_ingress"; do

      log "+----------------------------------------------------------------------+"
      log "Testing with Policy=$policy, Service=$service, Conntrack=$state"
      log "+----------------------------------------------------------------------+"

      case $policy in
        "many_egress")
          policy_many_egress;;
        "egress")
          policy_single_egress;;
        "many_ingress")
          policy_many_ingress;;
        "ingress")
          policy_single_ingress;;
        "egress_and_ingress")
          policy_egress_and_ingress;;
      esac

      proxy_test
    done
  done
done

log "deleting all services from Cilium"
cilium service delete --all
log "deleting all policies from Cilium"
cilium policy delete --all 2> /dev/null || true
log "removing containers"
docker rm -f server1 server2 client 2> /dev/null || true

test_succeeded "${TEST_NAME}"
