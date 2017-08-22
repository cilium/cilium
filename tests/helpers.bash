#!/usr/bin/env bash

CILIUM_FILES="cilium-files"
DUMP_FILE=$(mktemp)
MONITOR_PID=""
LAST_LOG_DATE=""

# Variables used during Jenkins builds.
BUILD_NUM="${BUILD_NUMBER:-0}"
JOB_BASE="${JOB_BASE_NAME:-local}"
BUILD_ID="${JOB_BASE}-${BUILD_NUM}"

AGENT_SOCK_PATH=/var/run/cilium/cilium.sock

# Prefer local build if binary file detected.
for bin in "../cilium/cilium" \
  "../daemon/cilium-agent" \
  "../plugins/cilium-docker/cilium-docker"; do
        if [ -f $bin ]; then
          export PATH=$PWD/`dirname $bin`:$PATH
        fi
done

function monitor_start {
	cilium monitor -v $@ > $DUMP_FILE &
	MONITOR_PID=$!
}

function monitor_resume {
	cilium monitor -v $@ >> $DUMP_FILE &
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
	until [ "$(cilium endpoint list | grep -v 'not-ready' | grep ready -c )" -eq "$1" ]; do
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

	# Wait some time for at least one endpoint to get into regenerating state
	# FIXME: Remove when this is reliable
	sleep 5

	local sleep_time=1
	local iter=0
	local found=$(kubectl -n ${NAMESPACE} exec ${CILIUM_POD} cilium endpoint list | grep -v 'not-ready' | grep -c 'ready' || true)
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
		found=$(kubectl -n ${NAMESPACE} exec ${CILIUM_POD} cilium endpoint list | grep -v 'not-ready' | grep -c 'ready' || true)
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
        # FIXME by the time this executed, it's not guaranteed that we
        # don't skip a regenerating
        sleep 2s
        if ! cilium endpoint list | grep regenerating; then
            break
        fi
        micro_sleep
    done
    set -x
}

function wait_for_daemon_set_not_ready {
	set +x

	if [ "$#" -ne 2 ]; then
		echo "wait_for_daemon_set_not_ready: illegal number of parameters"
		exit 1
	fi

	local namespace="${1}"
	local name="${2}"

	echo "Waiting for instances of Cilium daemon $name in namespace $namespace to be clean up"

	local sleep_time=2
	local iter=0
	local found="0"
	until [[ "$found" -eq "1" ]]; do
		if [[ $((iter++)) -gt $((5*60/$sleep_time)) ]]; then
			echo ""
			echo "Timeout while waiting for cilium agent to be clean up by kubernetes"
			print_k8s_cilium_logs
			exit 1
		else
			kubectl -n ${namespace} get pods -o wide
			sleep $sleep_time
		fi
		kubectl get pods -n ${namespace} | grep ${name} -q
		found=$?
	done

	set -x
	kubectl -n kube-system get pods -o wide
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
    namespace=${2:-default}
    echo "Waiting for ${pod} pod to be Running..."
    while [[ "$(kubectl get pods -n ${namespace} -o wide | grep ${pod} | grep -c Running)" -ne "1" ]] ; do
        micro_sleep
    done
    set -x
}

function wait_for_no_pods {
  set +x
  namespace=${1:-default}
  echo "Waiting for no pods to be Running in namespace ${namespace}"
  kubectl get pods -n ${namespace} -o wide
  while [[ "$(kubectl get pods -n ${namespace} -o wide 2>&1 | grep -c 'No resources found')" -ne "1" ]] ; do
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

# Wait for healthy k8s cluster on $1 nodes
function wait_for_healthy_k8s_cluster {
	set +x
	local NNODES=$1
	echo "Waiting for healthy k8s cluster with $NNODES nodes"

	local sleep_time=2
	local iter=0
	local found=$(kubectl get cs | grep -v "STATUS" | grep -c "Healthy")
	until [[ "$found" -eq "3" ]]; do
		if [[ $((iter++)) -gt $((1*60/$sleep_time)) ]]; then
			echo ""
			echo "Timeout while waiting for healthy kubernetes cluster"
			exit 1
		else
			kubectl get cs
			echo "K8S Components ready: [${found}/3]"
			sleep $sleep_time
		fi
		found=$(kubectl get cs | grep -v "STATUS" | grep -c "Healthy")
	done
	set -x
	kubectl get cs
	local iter=0
	local found=$(kubectl get nodes | grep Ready -c)
	until [[ "$found" -eq "$NNODES" ]]; do
		if [[ $((iter++)) -gt $((1*60/$sleep_time)) ]]; then
			echo ""
			echo "Timeout while waiting for all nodes to be Ready"
			exit 1
		else
			kubectl get nodes
			echo "Nodes ready [${found}/${NNODES}]"
			sleep $sleep_time
		fi
		found=$(kubectl get nodes | grep Ready -c)
	done
}

function gather_files {
    set -xv
    TEST_NAME=$1
    TEST_SUITE=$2
    CILIUM_ROOT="src/github.com/cilium/cilium"
    if [ -z "${TEST_SUITE}" ]; then 
      TEST_SUITE="runtime-tests"
    fi
    if [ -z "${GOPATH}" ]; then 
      local GOPATH="/home/vagrant/go"
    fi 
    if [[ "${TEST_SUITE}" == "runtime-tests" ]]; then
      CILIUM_DIR="${GOPATH}/${CILIUM_ROOT}/tests/cilium-files/${TEST_NAME}"
    elif [[ "${TEST_SUITE}" == "k8s-tests" ]]; then 
      CILIUM_DIR="${GOPATH}/${CILIUM_ROOT}/tests/k8s/tests/cilium-files/${TEST_NAME}"
    else
      echo "${TEST_SUITE} not a valid value, continuing"
      CILIUM_DIR="${GOPATH}/${CILIUM_ROOT}/tests/cilium-files/${TEST_NAME}"
    fi 
    RUN="/var/run/cilium"
    LIB="/var/lib/cilium"
    RUN_DIR="${CILIUM_DIR}${RUN}"
    LIB_DIR="${CILIUM_DIR}${LIB}"
    mkdir -p ${CILIUM_DIR}
    mkdir -p ${RUN_DIR}
    mkdir -p ${LIB_DIR}
    sudo cp -r ${RUN}/state ${RUN_DIR} || true
    sudo cp -r ${LIB}/* ${LIB_DIR} || true 
    find ${CILIUM_DIR} -type d -exec sudo chmod 777 {} \;
    find ${CILIUM_DIR} -exec sudo chmod a+r {} \;
}

function print_k8s_cilium_logs {
	for pod in $(kubectl -n kube-system get pods -o wide| grep cilium | awk '{print $1}'); do
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
			kubectl -n kube-system get pods -o wide
			echo -n " [${found}/${n_ds_expected}]"
			sleep $sleep_time
		fi
		found=$(kubectl get ds -n ${namespace} ${name} 2>&1 | awk 'NR==2{ print $4 }')
	done

	set -x
	kubectl -n kube-system get pods -o wide
}

function k8s_wait_for_cilium_status_ready {
	local pod
	local namespace=$1
	local pods=$(kubectl -n $namespace get pods -l k8s-app=cilium | grep cilium- | awk '{print $1}')

	for pod in $pods; do
	    wait_for_kubectl_cilium_status $namespace $pod
	done
}

function k8s_count_all_cluster_cilium_eps {
	local total=0
	local pod
	local namespace=$1
	local pods=$(kubectl -n $namespace get pods -l k8s-app=cilium | grep cilium- | awk '{print $1}')

	for pod in $pods; do
		local n_eps=$(kubectl -n $namespace exec $pod -- cilium endpoint list --no-headers | wc -l)
		total=$(( $total + $n_eps ))
	done

    echo "$total"
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

function k8s_apply_policy {
	declare -A currentRevison
	local i
	local pod
	local namespace=$1
	local policy=$2
	local pods=$(kubectl -n $namespace get pods -l k8s-app=cilium | grep cilium- | awk '{print $1}')

	for pod in $pods; do
		local rev=$(kubectl -n $namespace exec $pod -- cilium policy get | grep Revision: | awk '{print $2}')
		currentRevison[$pod]=$rev
	done

	echo "Current policy revisions:"
	for i in "${!currentRevison[@]}"
	do
		echo "  $i: ${currentRevison[$i]}"
	done

	kubectl create -f $policy

	for pod in $pods; do
		local nextRev=$(expr ${currentRevison[$pod]} + 1)
		echo "Waiting for agent $pod endpoints to get to revision $nextRev"
		kubectl -n $namespace exec $pod -- cilium policy wait $nextRev
	done

	# Adding sleep as workaround for l7 stresstests
	sleep 10s
}

function k8s_delete_policy {
        declare -A currentRevison
        local i
        local pod
        local namespace=$1
        local policy=$2
        local pods=$(kubectl -n $namespace get pods -l k8s-app=cilium | grep cilium- | awk '{print $1}')

        for pod in $pods; do
                local rev=$(kubectl -n $namespace exec $pod -- cilium policy get | grep Revision: | awk '{print $2}')
                currentRevison[$pod]=$rev
        done

        echo "Current policy revisions:"
        for i in "${!currentRevison[@]}"
        do
                echo "  $i: ${currentRevison[$i]}"
        done

        kubectl delete -f $policy

        for pod in $pods; do
                local nextRev=$(expr ${currentRevison[$pod]} + 1)
                echo "Waiting for agent $pod endpoints to get to revision $nextRev"
                kubectl -n $namespace exec $pod -- cilium policy wait $nextRev
        done

        # Adding sleep as workaround for l7 stresstests
        sleep 10s
}

function policy_delete_and_wait {
	rev=$(cilium policy delete $* | grep Revision: | awk '{print $2}')
	timeout 120s cilium policy wait $rev
}

function policy_import_and_wait {
	rev=$(cilium policy import $* | grep Revision: | awk '{print $2}')
	timeout 120s cilium policy wait $rev
}

function get_vm_identity_file {
  local VM_NAME=$1
  vagrant ssh-config ${VM_NAME} | grep IdentityFile | awk '{print $2}'
}

function get_vm_ssh_port {
  local VM_NAME=$1
  vagrant ssh-config ${VM_NAME} | grep Port | awk '{ print $2 }'
}

function copy_files_vm {
  local VM_NAME=$1 
  local FILES_DIR=$2

  # Check that the VM is running before we try to gather logs from it.
  check_vm_running $VM_NAME

  echo "----- getting the VM identity file for $VM_NAME -----"
  local ID_FILE=$(get_vm_identity_file $VM_NAME)
  echo "----- getting the port for $VM_NAME to SSH -----"
  local PORT=$(get_vm_ssh_port $VM_NAME)

  echo "----- getting cilium logs from $VM_NAME -----"
  vagrant ssh $VM_NAME -c 'sudo -E bash -c "journalctl --no-pager -u cilium > /home/vagrant/go/src/github.com/cilium/cilium/tests/cilium-files/cilium-logs && chmod a+r /home/vagrant/go/src/github.com/cilium/cilium/tests/cilium-files/cilium-logs"'

  echo "----- listing all logs that will be gathered from $VM_NAME -----"
  vagrant ssh $VM_NAME -c 'ls -altr /home/vagrant/go/src/github.com/cilium/cilium/tests/cilium-files'

  echo "----- copying logs from $VM_NAME onto VM host for accessibility after VM is destroyed -----"
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r -P ${PORT} -i ${ID_FILE} vagrant@127.0.0.1:/home/vagrant/go/src/github.com/cilium/cilium/${FILES_DIR} ${WORKSPACE}/cilium-files-${VM_NAME}
}

function get_k8s_vm_name {
  local VM_PREFIX=$1
  
  if [ ! -z ${BUILD_NUMBER} ] ; then
    local BUILD_ID_NAME="-build-${BUILD_ID}"
  fi
  echo "${VM_PREFIX}${BUILD_ID_NAME}"
}

function get_cilium_master_vm_name {
  if [ ! -z ${K8STAG} ] ; then
    local K8S_TAG="${K8STAG:-k8s}"
  fi

  if [ ! -z ${BUILD_NUMBER} ] ; then
    local BUILD_ID_NAME="-build-${BUILD_ID}"
  fi
  
  echo "cilium${K8S_TAG}-master${BUILD_ID_NAME}"
}

function check_vm_running {
  local VM=$1
  echo "----- getting status of VM $VM -----"
  vagrant status $VM
  echo "----- done getting status of VM $VM -----"

  local VM_STATUS=`vagrant status $VM | grep $VM | awk '{print $2}'`
  if [[ "${VM_STATUS}" != "running" ]]; then 
    echo "$VM is not in \"running\" state; exiting"
    exit 0
  else 
    echo "$VM is \"running\" continuing"
  fi
}

function wait_for_agent_socket {
  MAX_WAIT=$1
  local i=0

  while [ "$i" -lt "$MAX_WAIT" ]; do
    micro_sleep
    i=$[$i+1]
    if [ -S $AGENT_SOCK_PATH ]; then
      return
    fi
  done
  abort "Waiting for agent socket, timed out"
}

function wait_for_kill {
  TARGET_PID=$1
  MAX_WAIT=$2
  local i=0

  while [ $i -lt $MAX_WAIT ]; do
    micro_sleep
    i=$[$i+1]
    if ! ps -p $TARGET_PID > /dev/null; then
      return
    fi
  done
  abort "Waiting for agent process to be killed, timed out"
}
