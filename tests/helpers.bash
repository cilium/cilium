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
    echo "Waiting for all endpoints to be ready"
	until [ "$(cilium endpoint list | grep ready -c)" -eq "$1" ]; do
	    micro_sleep
	done
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
}

function wait_for_cilium_ep_gen {
    set +x
    while true; do
        if ! cilium endpoint list | grep regenerating; then
            break
        fi
        micro_sleep
    done
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
}

function wait_for_running_pod {
    set +x
    pod=$1
    echo "Waiting for ${pod} pod to be Running..."
    while [[ "$(kubectl get pods | grep ${pod} | grep Running -c)" -ne "1" ]] ; do
        micro_sleep
    done
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

function wait_for_daemon_set_ready {
    set +x
    if [ "$#" -ne 3 ]; then
        echo "wait_for_daemon_set_ready: illegal number of parameters"
        exit 1
    fi
    namespace="${1}"
    name="${2}"
    n_ds_expected="${3}"
    echo "Waiting for ${name} daemon set to be ready..."
    until [ "$(kubectl get ds -n ${namespace} ${name} 2>&1 | awk 'NR==2{ print $4 }')" = "${n_ds_expected}" ]; do
	    micro_sleep
    done
    set -x
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
    namespace="${1}"
    name="${2}"
    port="${3}"

    echo "Waiting for ${name} service endpoints to be ready"
    until [ "$(kubectl get endpoints -n ${namespace} ${name} | grep ":${port}")" ]; do
        micro_sleep
    done
    set -x
}