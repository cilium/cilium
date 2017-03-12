#!/bin/bash

source "./helpers.bash"

set -e

TEST_NET="cilium"
NETPERF_IMAGE="tgraf/nettools"
TEST_TIME=30
SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"
SERVER_NAME="server"
CLIENT_NAME="client"
HEADERS=${HEADERS_OFF:+"-P 0"}

# Only run these tests if BENCHMARK=1 and GCE=1 has been set
if [ -z ${BENCHMARK} ] || [ -z ${GCE} ]; then
	exit 0
fi

function create_k8s_files {
    sed -e "s+NETPERF_IMAGE+${NETPERF_IMAGE}+" \
        -e "s+CLIENT_NAME+${CLIENT_NAME}+" \
        -e "s+CLIENT_LABEL+${CLIENT_LABEL}+" \
        ./gce-deployment/client.json.sed  > ./gce-deployment/client.json
    sed -e "s+NETPERF_IMAGE+${NETPERF_IMAGE}+" \
        -e "s+SERVER_NAME+${SERVER_NAME}+" \
        -e "s+SERVER_LABEL+${SERVER_LABEL}+" \
        ./gce-deployment/server.json.sed  > ./gce-deployment/server.json
}

create_k8s_files

function cleanup_k8s {
    kubectl delete -f ./gce-deployment/client.json || true
    kubectl delete -f ./gce-deployment/server.json || true
}

trap cleanup_k8s EXIT

kubectl create -f ./gce-deployment/client.json
kubectl create -f ./gce-deployment/server.json

while [[ "$(kubectl get pods | grep ${CLIENT_NAME} | grep Running -c)" -ne "1" ]] ; do
    echo "Waiting for ${CLIENT_NAME} pod to be Running..."
    sleep 2s
done

while [[ "$(kubectl get pods | grep ${SERVER_NAME} | grep Running -c)" -ne "1" ]] ; do
    echo "Waiting for ${SERVER_NAME} pod to be Running..."
    sleep 2s
done

echo "Getting Client and Server IPv6, IPv4 and ID from containers"

server_pod=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep "${SERVER_NAME}")
client_pod=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep "${CLIENT_NAME}")

server_worker=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' | grep "${SERVER_NAME}" | cut -d' ' -f2)
client_worker=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' | grep "${CLIENT_NAME}" | cut -d' ' -f2)

server_cilium=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' | grep cilium | grep "${server_worker}" | cut -d' ' -f1)
client_cilium=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' | grep cilium | grep "${client_worker}" | cut -d' ' -f1)

echo "..."

function cleanup_cilium {
    cleanup_k8s

    for line in ${server_cilium} ${client_cilium}; do
        kubectl exec -i ${line} -- cilium daemon config DropNotification=true Debug=true
    done
}

trap cleanup_cilium EXIT

CLIENT_IP=$(kubectl exec ${client_pod} -- ip -6 a s | grep global | tr -s ' ' | cut -d' ' -f 3 | sed 's:/.*::')
CLIENT_IP4=$(kubectl exec ${client_pod} -- ip -4 a s | grep global | tr -s ' ' | cut -d' ' -f 3 | sed 's:/.*::')
CLIENT_ID=$(kubectl exec ${client_cilium} -- cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')
SERVER_IP=$(kubectl exec ${server_pod} -- ip -6 a s | grep global | tr -s ' ' | cut -d' ' -f 3 | sed 's:/.*::')
SERVER_IP4=$(kubectl exec ${server_pod} -- ip -4 a s | grep global | tr -s ' ' | cut -d' ' -f 3 | sed 's:/.*::')
SERVER_ID=$(kubectl exec ${server_cilium} -- cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')

HOST_IP=$(echo $SERVER_IP | sed -e 's/:[0-9a-f]\{4\}$/:ffff/')
SERVER_DEV=$(kubectl exec ${server_cilium} -- cilium endpoint inspect $SERVER_ID | grep interface-name | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')
NODE_MAC=$(kubectl exec ${server_cilium} -- cilium endpoint inspect $SERVER_ID | grep node-mac | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')
LXC_MAC=$(kubectl exec ${server_cilium} -- cilium endpoint inspect $SERVER_ID | grep lxc-mac | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')

echo "... Done"

sleep 5
set -x

cat <<EOF | kubectl exec -i "${server_cilium}" -- cilium -D policy import -
{
    "name": "root",
    "rules": [
	{
	    "coverage": [
		{
		    "key": "${SERVER_LABEL}",
		    "source": "k8s"
		}
	    ],
	    "allow": [
		{
		    "action": "always-accept",
		    "label": {
			"key": "${CLIENT_LABEL}",
			"source": "k8s"
		    }
		}
	    ]
	}
    ]
}
EOF

function perf_test() {
	kubectl exec ${client_pod} -- netperf -6 $HEADERS -l $TEST_TIME -t TCP_STREAM -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		kubectl exec ${client_pod} -- netperf -4 $HEADERS -l $TEST_TIME -t TCP_STREAM -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP endpoint"
		}
	fi

	kubectl exec ${client_pod} -- netperf -6 $HEADERS -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		kubectl exec ${client_pod} -- netperf -4 $HEADERS -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP endpoint"
		}
	fi

	kubectl exec ${client_pod} -- netperf -6 $HEADERS -l $TEST_TIME -t UDP_STREAM -H $SERVER_IP -- -R1 || {
		abort "Error: Unable to reach netperf UDP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		kubectl exec ${client_pod} -- netperf -4 $HEADERS -l $TEST_TIME -t UDP_STREAM -H $SERVER_IP4 -- -R1 || {
			abort "Error: Unable to reach netperf UDP endpoint"
		}
	fi

	kubectl exec ${client_pod} -- netperf -6 $HEADERS -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP -- -m 256 || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	kubectl exec ${client_pod} -- super_netperf 8 -6 -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		kubectl exec ${client_pod} -- super_netperf 8 -4 -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP endpoint"
		}
	fi

	kubectl exec ${client_pod} -- netperf -6 $HEADERS -l $TEST_TIME -t TCP_RR -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		kubectl exec ${client_pod} -- netperf -4 $HEADERS -l $TEST_TIME -t TCP_RR -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP endpoint"
		}
	fi

# FIXME
#	kubectl exec ${client_pod} -- netperf -6 $HEADERS -l $TEST_TIME -t TCP_CRR -H $SERVER_IP || {
#		abort "Error: Unable to reach netperf TCP endpoint"
#	}
#
#	if [ $SERVER_IP4 ]; then
#		kubectl exec ${client_pod} -- netperf -4 $HEADERS -l $TEST_TIME -t TCP_CRR -H $SERVER_IP4 || {
#			abort "Error: Unable to reach netperf TCP endpoint"
#		}
#	fi

	kubectl exec ${client_pod} -- netperf -6 $HEADERS -l $TEST_TIME -t UDP_RR -H $SERVER_IP -- -R1 || {
		abort "Error: Unable to reach netperf UDP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		kubectl exec ${client_pod} -- netperf -4 $HEADERS -l $TEST_TIME -t UDP_RR -H $SERVER_IP4 -- -R1 || {
			abort "Error: Unable to reach netperf UDP endpoint"
		}
	fi
}

kubectl exec ${server_cilium} -- cilium daemon config DropNotification=false Debug=false
kubectl exec ${client_cilium} -- cilium daemon config DropNotification=false Debug=false
kubectl exec ${server_cilium} -- cilium endpoint config $SERVER_ID DropNotification=false Debug=false
kubectl exec ${client_cilium} -- cilium endpoint config $CLIENT_ID DropNotification=false Debug=false
perf_test

kubectl exec ${server_cilium} -- cilium endpoint config $SERVER_ID ConntrackAccounting=false
kubectl exec ${client_cilium} -- cilium endpoint config $CLIENT_ID ConntrackAccounting=false
perf_test

# FIXME
echo "Conntrack=false test won't be run!"
#kubectl exec ${server_cilium} -- cilium endpoint config $SERVER_ID Conntrack=false
#kubectl exec ${client_cilium} -- cilium endpoint config $CLIENT_ID Conntrack=false
#perf_test

kubectl exec ${server_cilium} -- cilium endpoint config $SERVER_ID Policy=false
kubectl exec ${client_cilium} -- cilium endpoint config $CLIENT_ID Policy=false
perf_test

kubectl exec ${server_cilium} -- cilium -D policy delete "${SERVER_LABEL}"
