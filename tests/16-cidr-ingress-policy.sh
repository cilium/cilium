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
ID_SERVICE3="id.service3"

IPV4_HOST=192.168.254.254
IPV4_OTHERHOST=192.168.254.111
IPV4_OTHERNET=99.11.0.0/16
IPV6_HOST=fdff::ff

function cleanup {
  ip addr del dev lo ${IPV4_HOST}/32 2> /dev/null || true
  ip addr del dev lo ${IPV6_HOST}/128 2> /dev/null || true
  cilium policy delete --all 2> /dev/null || true
  docker rm -f ${HTTPD_CONTAINER_NAME}  2> /dev/null || true
  remove_cilium_docker_network
  monitor_stop
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

trap finish_test EXIT

cleanup
monitor_start
logs_clear

log "checking cilium status"
cilium status

log "creating Docker network of type Cilium"
create_cilium_docker_network

log "starting example service with Docker"
docker run -d --name ${HTTPD_CONTAINER_NAME} --net ${TEST_NET} -l "${ID_SERVICE1}" cilium/demo-httpd

IPV6_PREFIX=$(docker inspect --format "{{ .NetworkSettings.Networks.${TEST_NET}.IPv6Gateway }}" ${HTTPD_CONTAINER_NAME})/112
IPV4_ADDRESS=$(docker inspect --format "{{ .NetworkSettings.Networks.${TEST_NET}.IPAddress }}" ${HTTPD_CONTAINER_NAME})
IPV4_PREFIX=$(expr $IPV4_ADDRESS : '\([0-9]*\.[0-9]*\.\)')0.0/16

cilium config PolicyEnforcement=always

ip addr add dev lo ${IPV4_HOST}/32
ip addr add dev lo ${IPV6_HOST}/128

policy_delete_and_wait "--all"
wait_for_cilium_ep_gen
cilium endpoint list

monitor_clear
log "pinging host from service2 (should NOT work)"

set +e
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 14 ${IPV4_HOST} && {
  abort "Error: Unexpected success pinging host (${IPV4_HOST}) from service2"
}
set -e

log "importing L3 CIDR policy for IPv4 egress"
policy_delete_and_wait "--all"
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"${ID_SERVICE2}":""}},
    "egress": [{
	"toCIDR": [
	    "${IPV4_OTHERHOST}/24",
	    "${IPV4_OTHERHOST}/20"
	]
    }]
}]
EOF

monitor_clear
log "pinging host from service2 (should work)"
cilium policy get

docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 14 ${IPV4_HOST} || {
  abort "Error: Could not ping host (${IPV4_HOST}) from service2"
}

policy_delete_and_wait "--all"
monitor_clear

log "pinging host from service2 (should NOT work)"
set +e
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping6 -c 14 ${IPV6_HOST} && {
  abort "Error: Unexpected success pinging host (${IPV6_HOST}) from service2"
}
set -e

log "importing L3 CIDR policy for IPv6 egress"
policy_delete_and_wait "--all"
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"${ID_SERVICE2}":""}},
    "egress": [{
	"toCIDR": [
	    "${IPV6_HOST}"
	]
    }]
}]
EOF

monitor_clear
log "pinging host from service2 (should work)"
cilium policy get
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping6 -c 14 ${IPV6_HOST} || {
  abort "Error: Could not ping host (${IPV6_HOST}) from service2"
}

log "importing policy"
policy_delete_and_wait "--all"
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"${ID_SERVICE1}":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"${ID_SERVICE2}":""}}
	]
    }]
}]
EOF

monitor_clear
log "pinging service1 from service2 (should work)"
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 14 ${HTTPD_CONTAINER_NAME} || {
  abort "Error: Could not ping ${HTTPD_CONTAINER_NAME} from service2"
}

monitor_clear
log "pinging service1 from service2 (IPv6 - should work)"
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping6 -c 14 ${HTTPD_CONTAINER_NAME} || {
  abort "Error: Could not ping ${HTTPD_CONTAINER_NAME} from service2"
}

monitor_clear
log "pinging service1 from service3 (should NOT work)"
set +e
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE3}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 14 ${HTTPD_CONTAINER_NAME} && {
  abort "Error: Unexpected success pinging ${HTTPD_CONTAINER_NAME} from service3"
}
set -e

monitor_clear
log "pinging service1 from service3 (IPv6 - should NOT work)"
set +e
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE3}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping6 -c 14 ${HTTPD_CONTAINER_NAME} && {
  abort "Error: Unexpected success pinging ${HTTPD_CONTAINER_NAME} from service3"
}
set -e

log "creating cidr_aware_policy.json with matching prefixes"
echo "IPv6 prefix: $IPV6_PREFIX"
echo "IPv4 prefix: $IPV4_PREFIX"
policy_delete_and_wait "--all"
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"${ID_SERVICE1}":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"${ID_SERVICE2}":""}}
	],
	"fromCIDR": [
	    "${IPV4_PREFIX}",
	    "${IPV6_PREFIX}"
	]
    }]
}]
EOF

monitor_clear
cilium policy get
log "pinging service1 from service3 (should work)"
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE3}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 14 ${HTTPD_CONTAINER_NAME}  || {
  abort "Error: Could not ping ${HTTPD_CONTAINER_NAME} from service3"
}

monitor_clear
log "pinging service1 from service3 (IPv6 - should work)"
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE3}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping6 -c 14 ${HTTPD_CONTAINER_NAME}  || {
  abort "Error: Could not ping ${HTTPD_CONTAINER_NAME} from service3"
}

log "creating cidr_aware_policy.json with non-matching prefix"
policy_delete_and_wait "--all"
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"${ID_SERVICE1}":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"${ID_SERVICE2}":""}}
	],
	"fromCIDR": [
	    "${IPV4_OTHERNET}"
	]
    }]
}]
EOF

monitor_clear
set +e
log "pinging service1 from service3 (should NOT work)"
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE3}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 14 ${HTTPD_CONTAINER_NAME} && {
  abort "Error: Unexpected success pinging ${HTTPD_CONTAINER_NAME} from service3"
}
set -e

monitor_clear
log "pinging service1 from service3 (IPv6 - should NOT work)"
set +e
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE3}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping6 -c 14 ${HTTPD_CONTAINER_NAME} && {
  abort "Error: Unexpected success pinging ${HTTPD_CONTAINER_NAME} from service3"
}
set -e

policy_delete_and_wait "--all"

test_succeeded "${TEST_NAME}"
