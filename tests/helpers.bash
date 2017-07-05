#!/usr/bin/env bash

DUMP_FILE=$(mktemp)
MONITOR_PID=""
LAST_LOG_DATE=""

function monitor_start {
	cilium monitor $@ > $DUMP_FILE &
	MONITOR_PID=$!
}

function monitor_resume {
	cilium monitor $@ >> $DUMP_FILE &
	MONITOR_PID=$!
}

function monitor_clear {
	set +x
	cp /dev/null $DUMP_FILE
	nstat > /dev/null
	set -x
}

function monitor_dump {
	nstat
	cat $DUMP_FILE
}

function monitor_stop {
	if [ ! -z "$MONITOR_PID" ]; then
		kill $MONITOR_PID || true
	fi
}

function logs_clear {
    LAST_LOG_DATE="$(date +'%F %T')"
}

function abort {
	set +x

	echo "------------------------------------------------------------------------"
	echo "                            Test Failed"
	echo "$*"
	echo ""
	echo "------------------------------------------------------------------------"

	monitor_dump
	monitor_stop

	echo "------------------------------------------------------------------------"
	echo "                            Cilium logs"
	journalctl --no-pager --since "${LAST_LOG_DATE}" -u cilium
	echo ""
	echo "------------------------------------------------------------------------"

	exit 1
}

function micro_sleep {
    sleep 0.5
}

function wait_for_endpoints {
    set +x
    echo -n "Waiting for $1 cilium endpoints to become ready"
	until [ "$(cilium endpoint list | grep ready -c)" -eq "$1" ]; do
	    micro_sleep
	    echo -n "."
	done
	set -x
}

function wait_for_k8s_endpoints {
	set +x
	local NAMESPACE=$1
	local CILIUM_POD=$2
	local NUM=$3
	echo "Waiting for $NUM endpoints in namespace $NAMESPACE managed by $CILIUM_POD"

	local sleep_time=1
	local iter=0
	local found=$(kubectl -n ${NAMESPACE} exec ${CILIUM_POD} cilium endpoint list | grep -c 'ready')
	echo "found: $found"
	while [[ "$found" -ne "$NUM" ]]; do
		if [[ $((iter++)) -gt $((5*60/$sleep_time)) ]]; then
			echo ""
			echo "Timeout while waiting for $NUM endpoints"
			exit 1
		else
			kubectl -n ${NAMESPACE} exec ${CILIUM_POD} cilium endpoint list
			echo -n " [${found}/${NUM}]"
			sleep $sleep_time
		fi
		found=$(kubectl -n ${NAMESPACE} exec ${CILIUM_POD} cilium endpoint list | grep -c 'ready')
		echo "found: $found"
	done

	set -x
	kubectl -n ${NAMESPACE} exec ${CILIUM_POD} cilium endpoint list
}

function wait_for_cilium_status {
    set +x
	while ! cilium status; do
	    micro_sleep
	done
}

function wait_for_kubectl_cilium_status {
    set +x
    namespace=$1
    pod=$2

    echo "Waiting for Cilium to spin up"
    while ! kubectl -n ${namespace} exec ${pod} cilium status; do
        micro_sleep
    done
    set -x
}

function wait_for_cilium_ep_gen {
    set +x
    while true; do
        if ! cilium endpoint list | grep regenerating; then
            break
        fi
        micro_sleep
    done
    set -x
}

function wait_for_policy_enforcement {
    while true; do
        if ! cilium endpoint list | grep Disabled; then
            break
        fi
        micro_sleep
    done
}

function count_lines_in_log {
    echo `wc -l $DUMP_FILE | awk '{ print $1 }'`
}

function wait_for_log_entries {
    set +x
    expected=$(($1 + $(count_lines_in_log)))

    while [ $(count_lines_in_log) -lt "$expected" ]; do
        micro_sleep
    done
    set -x
}

function wait_for_docker_ipv6_addr {
    set +x
    name=$1
    while true; do
        if [[ "$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' ${name})" != "" ]];
         then
             break
         fi
         micro_sleep
    done
    set -x
}

function wait_for_running_pod {
    set +x
    pod=$1
    echo "Waiting for ${pod} pod to be Running..."
    while [[ "$(kubectl get pods | grep ${pod} | grep -c Running)" -ne "1" ]] ; do
        micro_sleep
    done
    set -x
}

function wait_for_n_running_pods {
	set +x
	local NPODS=$1
	echo -n "Waiting for $NPODS running pods"

	local sleep_time=1
	local iter=0
	local found=$(kubectl get pod | grep Running -c || true)
	until [[ "$found" -eq "$NPODS" ]]; do
		if [[ $((iter++)) -gt $((5*60/$sleep_time)) ]]; then
			echo ""
			echo "Timeout while waiting for $NPODS running pods"
			exit 1
		else
			kubectl get pod -o wide
			echo -n " [${found}/${NPODS}]"
			sleep $sleep_time
		fi
		found=$(kubectl get pod | grep Running -c || true)
	done

	set -x
	kubectl get pod -o wide
}

# Wait for healthy k8s cluster
function wait_for_healthy_k8s_cluster {
	set +x
	local NNODES=$1
	echo -n "Waiting for healthy k8s cluster with $NNODES nodes"

	local sleep_time=2
	local iter=0
	local found=$(kubectl get cs | grep -v "STATUS" | grep -c "Healthy")
	until [[ "$found" -eq "$NNODES" ]]; do
		if [[ $((iter++)) -gt $((1*60/$sleep_time)) ]]; then
			echo ""
			echo "Timeout while waiting for healthy kubernetes cluster"
			exit 1
		else
			kubectl get cs
			echo -n " [${found}/${NNODES}]"
			sleep $sleep_time
		fi
		found=$(kubectl get cs | grep -v "STATUS" | grep -c "Healthy")
	done
	set -x
	kubectl get cs
}

function gather_files {
    TEST_NAME=$1
    CILIUM_DIR="${GOPATH}/src/github.com/cilium/cilium/tests/cilium-files/${TEST_NAME}"
    RUN="/var/run/cilium"
    LIB="/var/lib/cilium"
    RUN_DIR="${CILIUM_DIR}${RUN}"
    LIB_DIR="${CILIUM_DIR}${LIB}"
    mkdir -p ${CILIUM_DIR}
    mkdir -p ${RUN_DIR}
    mkdir -p ${LIB_DIR}
    sudo cp -r ${RUN}/state ${RUN_DIR}
    sudo cp -r ${LIB}/* ${LIB_DIR}
    find . -type d -exec sudo chmod 777 {} \;
    find ${CILIUM_DIR} -exec sudo chmod a+r {} \;
}

function print_k8s_cilium_logs {
	for pod in $(kubectl -n kube-system get pods | grep cilium | awk '{print $1}'); do
		kubectl -n kube-system logs $pod
		if [ $? -ne 0 ]; then
			kubectl -n kube-system logs $pod --previous
		fi
	done
}

function wait_for_daemon_set_ready {
	set +x

	if [ "$#" -ne 3 ]; then
		echo "wait_for_daemon_set_ready: illegal number of parameters"
		exit 1
	fi

	local namespace="${1}"
	local name="${2}"
	local n_ds_expected="${3}"

	echo "Waiting for $n_ds_expected instances of Cilium daemon $name in namespace $namespace to become ready"

	local sleep_time=2
	local iter=0
	local found="0"
	until [[ "$found" -eq "$n_ds_expected" ]]; do
		if [[ $((iter++)) -gt $((5*60/$sleep_time)) ]]; then
			echo ""
			echo "Timeout while waiting for cilium agent"
			print_k8s_cilium_logs
			exit 1
		else
			kubectl -n kube-system get ds
			kubectl -n kube-system get pods
			echo -n " [${found}/${n_ds_expected}]"
			sleep $sleep_time
		fi
		found=$(kubectl get ds -n ${namespace} ${name} 2>&1 | awk 'NR==2{ print $4 }')
	done

	set -x
	kubectl -n kube-system get pods
}

function wait_for_api_server_ready {
    set +x
    echo "Waiting for kube-apiserver to spin up"
    while ! kubectl get cs; do
        micro_sleep
    done
    set -x
}

function wait_for_service_endpoints_ready {
    set +x
    if [ "$#" -ne 3 ]; then
        echo "wait_for_service_endpoints_ready: illegal number of parameters"
        exit 1
    fi
    local namespace="${1}"
    local name="${2}"
    local port="${3}"

    echo "Waiting for ${name} service endpoints to be ready"
    until [ "$(kubectl get endpoints -n ${namespace} ${name} | grep ":${port}")" ]; do
        micro_sleep
    done
    set -x
}
