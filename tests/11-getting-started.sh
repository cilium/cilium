#!/bin/bash
set -e

source "./helpers.bash"

TEST_NET="cilium-net"
DEMO_CONTAINER="cilium/demo-client"
HTTPD_CONTAINER_NAME="service1-instance1"
ID_SERVICE1="id.service1"
ID_SERVICE2="id.service2"

function cleanup {
  gather_files 11-getting-started ${TEST_SUITE}
  cilium policy delete --all 2> /dev/null || true
  docker rm -f ${HTTPD_CONTAINER_NAME}  2> /dev/null || true
  docker network rm ${TEST_NET} 2> /dev/null || true
  monitor_stop
}

trap cleanup EXIT

cleanup
monitor_start
logs_clear

echo "------ checking cilium status ------"
cilium status

echo "------ creating Docker network of type Cilium ------"
docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium ${TEST_NET}

echo "------ starting example service with Docker ------"
docker run -d --name ${HTTPD_CONTAINER_NAME} --net ${TEST_NET} -l "${ID_SERVICE1}" cilium/demo-httpd

echo "------ creating l3_l4_policy.json ------"
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
echo "------ pinging service1 from service3 ------"
docker run --rm -i --net ${TEST_NET} -l "id.service3" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 5 ${HTTPD_CONTAINER_NAME} && {
  abort "Error: Unexpected success pinging ${HTTPD_CONTAINER_NAME} from service3"
}

monitor_clear
echo "------ pinging service1 from service2 ------"
docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" --cap-add NET_ADMIN ${DEMO_CONTAINER} ping -c 5 ${HTTPD_CONTAINER_NAME}  || {
  abort "Error: Could not ping ${HTTPD_CONTAINER_NAME} from service2"
}

monitor_clear
echo "------ performing HTTP GET on ${HTTPD_CONTAINER_NAME}/public from service2 ------"
RETURN=$(docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" ${DEMO_CONTAINER} /bin/bash -c "curl -s --output /dev/stderr -w '%{http_code}' -XGET http://${HTTPD_CONTAINER_NAME}/public")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
  abort "Error: Could not reach ${HTTPD_CONTAINER_NAME}/public on port 80"
fi

monitor_clear
echo "------ performing HTTP GET on ${HTTPD_CONTAINER_NAME}/private from service2 ------"
RETURN=$(docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" ${DEMO_CONTAINER} /bin/bash -c "curl -s --output /dev/stderr -w '%{http_code}' -XGET http://${HTTPD_CONTAINER_NAME}/private")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
  abort "Error: Could not reach ${HTTPD_CONTAINER_NAME}/private on port 80"
fi

echo "------ creating l7_aware_policy.json ------"
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
echo "------ performing HTTP GET on ${HTTPD_CONTAINER_NAME}/public from service2 ------"
RETURN=$(docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" ${DEMO_CONTAINER} /bin/bash -c "curl -s --output /dev/stderr -w '%{http_code}' -XGET http://${HTTPD_CONTAINER_NAME}/public")
if [[ "${RETURN//$'\n'}" != "200" ]]; then
  abort "Error: Could not reach ${HTTPD_CONTAINER_NAME}/public on port 80"
fi

monitor_clear
echo "------ performing HTTP GET on ${HTTPD_CONTAINER_NAME}/private from service2 ------"
RETURN=$(docker run --rm -i --net ${TEST_NET} -l "${ID_SERVICE2}" ${DEMO_CONTAINER} /bin/bash -c "curl -s --output /dev/stderr -w '%{http_code}' -XGET http://${HTTPD_CONTAINER_NAME}/private")
# FIXME: re-renable when redirect issue is resolved
#if [[ "${RETURN//$'\n'}" != "403" ]]; then
#  abort "Error: Unexpected success reaching ${HTTPD_CONTAINER_NAME}/private on port 80"
#fi

cilium policy delete --all


