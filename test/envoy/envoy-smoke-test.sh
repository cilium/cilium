#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

function cleanup {
  monitor_stop
  echo "Tip: Add '--debug-verbose=flow' into cilium options in /etc/sysconfig/cilium to get Envoy debug logging."
  # These are commented to allow for easier debugging, but are left as comments to remind how to clean up:
  #  cilium service delete --all 2> /dev/null || true
  #  cilium policy delete --all 2> /dev/null || true
  #  docker rm -f server1 server2 client 2> /dev/null || true
}

function finish_test {
  # Gathering files takes a long time and is not needed for live debugging.
  #  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

trap finish_test EXIT

SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

SVC_IP="f00d::1:1"
SVC_IP4="10.0.0.2"

cleanup
logs_clear

function no_service_init {
  cilium service delete --all
  SERVER_IP=$SERVER1_IP;
  SERVER_IP4=$SERVER1_IP4;
}

function service_init {
  log "beginning service init"
  cilium service update --frontend "$SVC_IP4:80" --id 2233 \
			--backends "$SERVER1_IP4:80" \
			--backends "$SERVER2_IP4:80"

  cilium service update --frontend "[$SVC_IP]:80" --id 2234 \
			--backends "[$SERVER1_IP]:80" \
			--backends "[$SERVER2_IP]:80"

  SERVER_IP=$SVC_IP
  SERVER_IP4=$SVC_IP4
  log "finished service init"
}

function proxy_init {
  log "beginning proxy_init"
  create_cilium_docker_network

  if [ -z `docker ps -q -f name=^/server1$` ] ; then
      docker run -dt --net=cilium --name server1 -l $SERVER_LABEL -v "$dir/testsite":/usr/local/apache2/htdocs/ httpd
  fi
  if [ -z `docker ps -q -f name=^/server2$` ] ; then
      docker run -dt --net=cilium --name server2 -l $SERVER_LABEL -v "$dir/testsite":/usr/local/apache2/htdocs/ httpd
  fi
  if [ -z `docker ps -q -f name=^/client$` ] ; then
      # use an unused loopback address on a reserved non-listening port with large retry timeout to make this pause "forever"
      docker run -dt --net=cilium --name client -l id.client curlimages/curl -s --retry-connrefused --retry-delay 1000000 --retry 5 127.242.139.58:967
  fi
  
  SERVER1_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server1)
  SERVER2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server2)
  SERVER1_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server1)
  SERVER2_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server2)

  SERVER_IP=$SERVER1_IP;
  SERVER_IP4=$SERVER1_IP4;

  wait_for_docker_ipv6_addr server1
  wait_for_docker_ipv6_addr server2
  wait_for_docker_ipv6_addr client

  log "waiting for endpoints to get identities"
  while [ `cilium endpoint list -o jsonpath='{range [*]}{.status.identity.id}{" "}{.status.identity.labels}{"\n"}' | grep '^[1-9][0-9]* .*id.\(server\|client\)' | cut -d ' ' -f1 | sort | uniq | wc -l` -ne 2 ] ; do
    log "waiting..."
    sleep 1
  done

  monitor_start
  log "finished proxy_init"
}

# Dummy policy to keep the containers in policy enforcement mode all the time
function policy_base {
  cilium policy delete --all
  cat <<EOF | policy_import_and_wait -
[{
    "labels": [{"key": "policy", "value": "enforced"}],
    "endpointSelector": {"matchLabels":{}},
    "ingress": [{}],
    "egress": [{}]
},{
    "labels": [{"key": "policy", "value": "test"}],
    "endpointSelector": {"matchLabels":{}},
    "ingress": [{}],
    "egress": [{}]
}]
EOF
}

function policy_single_egress {
  cilium policy delete policy=test
  cat <<EOF | policy_import_and_wait -
[{
    "labels": [{"key": "policy", "value": "test"}],
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}}
	]
    }]
},{
    "labels": [{"key": "policy", "value": "test"}],
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
  cilium policy delete policy=test
  cat <<EOF | policy_import_and_wait -
[{
    "labels": [{"key": "policy", "value": "test"}],
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}}
	]
    }]
},{
    "labels": [{"key": "policy", "value": "test"}],
    "endpointSelector": {"matchLabels":{"id.client":""}},
    "egress": [{
        "toEndpoints": [{"matchLabels":{"id.server":""}}],
	"toPorts": [{
	    "ports": [{"port": "80",   "protocol": "tcp"}],
	    "rules": {
                "HTTP": [{
		    "method": "GET",
		    "path": "/public"
                }]
	    }
	}]
    }, {
        "toEndpoints": [{"matchLabels":{"id.client":""}}],
	"toPorts": [{
	    "ports": [{"port": "80",   "protocol": "tcp"}],
	    "rules": {
                "HTTP": [{
		    "method": "GET",
		    "path": "/self"
                }]
	    }
	}]
    }, {
        "toEndpoints": [{"matchLabels":{"id.server":""}}],
	"toPorts": [{
	    "ports": [{"port": "8000", "protocol": "tcp"},
		      {"port": "8080", "protocol": "tcp"}],
	    "rules": {
                "HTTP": [{
		    "method": "PUT",
		    "path": "/publix"
                }]
	    }
	}]
    }]
}]
EOF
}

function policy_single_ingress {
  cilium policy delete policy=test
  cat <<EOF | policy_import_and_wait -
[{
    "labels": [{"key": "policy", "value": "test"}],
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
},{
    "labels": [{"key": "policy", "value": "test"}],
    "endpointSelector": {"matchLabels":{"id.client":""}},
    "egress": [{
	"toPorts": [{
	    "ports": [{"port": "80", "protocol": "tcp"}]
	}]
    }]
}]
EOF
}

function policy_many_ingress {
  cilium policy delete policy=test
  cat <<EOF | policy_import_and_wait -
[{
    "labels": [{"key": "policy", "value": "test"}],
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
},{
    "labels": [{"key": "policy", "value": "test"}],
    "endpointSelector": {"matchLabels":{"id.client":""}},
    "egress": [{
	"toPorts": [{
	    "ports": [{"port": "80", "protocol": "tcp"}]
	}]
    }]
}]
EOF
}

function policy_egress_and_ingress {
  cilium policy delete policy=test
  cat <<EOF | policy_import_and_wait -
[{
    "labels": [{"key": "policy", "value": "test"}],
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"id.client":""}}
	]
    }]
},{
    "labels": [{"key": "policy", "value": "test"}],
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
    "labels": [{"key": "policy", "value": "test"}],
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

  # Cilium launches Envoy with path normalization enabled by default, so '//public' will be seen as '/public'
  log "trying to reach server IPv4 at http://$SERVER_IP4:80//public from client (expected: 200)"
  RETURN=$(docker exec -i client curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80//public)
  if [[ "${RETURN//$'\n'}" != "200" ]]; then
    abort "GET /public, unexpected return ${RETURN//$'\n'} != 200"
  fi

  log "trying to reach server IPv6 at http://[$SERVER_IP]:80/public from client (expected: 200)"
  RETURN=$(docker exec -i client curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://[$SERVER_IP]:80/public)
  if [[ "${RETURN//$'\n'}" != "200" ]]; then
    abort "GET /public, unexpected return ${RETURN//$'\n'} != 200"
  fi

  log "trying to reach server IPv4 at http://$SERVER_IP4:80/private from client (expected: 403)"
  RETURN=$(docker exec -i client curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80/private)
  if [[ "${RETURN//$'\n'}" != "403" ]]; then
    abort "GET /private, unexpected return ${RETURN//$'\n'} != 403"
  fi

  log "trying to reach server IPv6 at http://[$SERVER_IP]:80/private from client (expected: 403)"
  RETURN=$(docker exec -i client curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://[$SERVER_IP]:80/private)
  if [[ "${RETURN//$'\n'}" != "403" ]]; then
    abort "GET /private, unexpected return ${RETURN//$'\n'} != 403"
  fi

  log "finished proxy test"
}

proxy_init

log "+----------------------------------------------------------------------+"
log "Testing without Policy"
log "+----------------------------------------------------------------------+"
# Cilium launches Envoy with path normalization enabled by default, so '//public' will be seen as '/public'
log "trying to reach server IPv4 at http://$SERVER_IP4:80//public from client (expected: 200)"
RETURN=$(docker exec -i client curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET http://$SERVER_IP4:80//public)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
  abort "GET /public, unexpected return ${RETURN//$'\n'} != 200"
fi

policy_base

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
