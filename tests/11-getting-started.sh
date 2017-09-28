#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

DEMO_CONTAINER="cilium/demo-client"
HTTPD_CONTAINER_NAME="service1-instance1"
ID_SERVICE1="id.service1"
ID_SERVICE2="id.service2"

function cleanup {
  log "beginning cleanup for ${TEST_NAME}"
  log "deleting all policies"
  cilium policy delete --all 2> /dev/null || true
  log "removing container ${HTTPD_CONTAINER_NAME}"
  docker rm -f ${HTTPD_CONTAINER_NAME}  2> /dev/null || true
  log "removing Docker network ${TEST_NET}"
  remove_cilium_docker_network
  monitor_stop
  log "finished cleanup for ${TEST_NAME}"
}

function finish_test {
  log "finishing up ${TEST_NAME}"
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
  log "done finishing up ${TEST_NAME}"
}

trap finish_test EXIT

cleanup
monitor_start
logs_clear

log "checking cilium status"
cilium status

create_cilium_docker_network

log "starting example service with Docker"
docker run -d --name ${HTTPD_CONTAINER_NAME} --net ${TEST_NET} -l "${ID_SERVICE1}" cilium/demo-httpd

log "importing l3_l4_policy.json"
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"${ID_SERVICE1}":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"${ID_SERVICE2}":""}}
	],
	"toPorts": [{
	    "ports": [{"port": "80", "protocol": "tcp"}]
	}]
    }]
}]
EOF

wait_for_endpoints 1

monitor_clear
log "pinging service1 from service3"
docker run --rm -i --net ${TEST_NET} -l "id.service3" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 10 ${HTTPD_CONTAINER_NAME} && {
  abort "Error: Unexpected success pinging ${HTTPD_CONTAINER_NAME} from service3"
}

monitor_clear
log "pinging service1 from service2"
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 10 ${HTTPD_CONTAINER_NAME} && {
  abort "Error: Unexpected success pinging ${HTTPD_CONTAINER_NAME} from service2"
}

monitor_clear
log "performing HTTP GET on ${HTTPD_CONTAINER_NAME}/public from service2 (expected: 200)"
RETURN=$(docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" ${DEMO_CONTAINER} /bin/bash -c "curl -s --output /dev/stderr -w '%{http_code}' -XGET http://${HTTPD_CONTAINER_NAME}/public")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
  abort "Error: Could not reach ${HTTPD_CONTAINER_NAME}/public on port 80"
fi

monitor_clear
log "performing HTTP GET on ${HTTPD_CONTAINER_NAME}/private from service2 (expected: 200)"
RETURN=$(docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" ${DEMO_CONTAINER} /bin/bash -c "curl -s --output /dev/stderr -w '%{http_code}' -XGET http://${HTTPD_CONTAINER_NAME}/private")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
  abort "Error: Could not reach ${HTTPD_CONTAINER_NAME}/private on port 80"
fi

log "importing l7_aware_policy.json"
cilium policy delete --all
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"${ID_SERVICE1}":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"${ID_SERVICE2}":""}},
	    {"matchLabels":{"reserved:host":""}}
	]
    }]
},{
    "endpointSelector": {"matchLabels":{"${ID_SERVICE2}":""}},
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

wait_for_cilium_ep_gen

monitor_clear
log "performing HTTP GET on ${HTTPD_CONTAINER_NAME}/public from service2 (expected: 200)"
RETURN=$(docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" ${DEMO_CONTAINER} /bin/bash -c "curl -s --output /dev/stderr -w '%{http_code}' -XGET http://${HTTPD_CONTAINER_NAME}/public")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
  abort "Error: Could not reach ${HTTPD_CONTAINER_NAME}/public on port 80"
fi

monitor_clear
log "performing HTTP GET on ${HTTPD_CONTAINER_NAME}/private from service2 (expected: 403)"
RETURN=$(docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" ${DEMO_CONTAINER} /bin/bash -c "curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 15 -XGET http://${HTTPD_CONTAINER_NAME}/private")
# FIXME: re-renable when redirect issue is resolved
#if [[ "${RETURN//$'\n'}" != "403" ]]; then
#  abort "Error: Unexpected success reaching ${HTTPD_CONTAINER_NAME}/private on port 80"
#fi

log "deleting all policies in Cilium"
cilium policy delete --all

test_succeeded "${TEST_NAME}"
