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

function check_num_params {
  local NUM_PARAMS=$1
  local NUM_EXPECTED_PARAMS=$2
  if [ "$NUM_PARAMS" -ne "$NUM_EXPECTED_PARAMS" ]; then
    echo "${FUNCNAME[ 1 ]}: invalid number of parameters, expected $NUM_EXPECTED_PARAMS parameter(s)"
    exit 1
  fi
}

function wait_for_endpoints {
  check_num_params "$#" "1"
  local NUM_DESIRED="$1"
  local CMD="cilium endpoint list | grep -v \"not-ready\" | grep ready -c || true"
  local INFO_CMD="cilium endpoint list"
  local MAX_MINS="2"
  local ERROR_OUTPUT="Timeout while waiting for $NUM_DESIRED endpoints"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
}

function k8s_num_ready {
	local NAMESPACE=$1
	local CILIUM_POD=$2
	local FILTER=$3

	kubectl -n ${NAMESPACE} exec ${CILIUM_POD} cilium endpoint list | grep $FILTER | grep -v 'not-ready' | grep -c 'ready' || true
}

function wait_for_k8s_endpoints {
  set +x
  check_num_params "$#" "4"
  local NAMESPACE=$1
  local CILIUM_POD=$2
  local NUM=$3
  local FILTER=$4
  echo "Waiting for $NUM endpoints in namespace $NAMESPACE managed by $CILIUM_POD"

  # Wait some time for at least one endpoint to get into regenerating state
  # FIXME: Remove when this is reliable
  sleep 5

  local sleep_time=1
  local iter=0
  local found=$(k8s_num_ready $NAMESPACE $CILIUM_POD $FILTER)
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
    found=$(k8s_num_ready $NAMESPACE $CILIUM_POD $FILTER)
    echo "found: $found"
  done

  set -x
  kubectl -n ${NAMESPACE} exec ${CILIUM_POD} cilium endpoint list
}

function wait_for_cilium_status {
  local NUM_DESIRED="1"
  local CMD="cilium status | grep 'Cilium:' | grep -c OK || true"
  local INFO_CMD="true"
  local MAX_MINS="1"
  local ERROR_OUTPUT="Timeout while waiting for Cilium to be ready"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
}

function wait_for_kubectl_cilium_status {
  set +x
  check_num_params "$#" "2"
  namespace=$1
  pod=$2
  local NUM_DESIRED="1"
  local CMD="kubectl -n ${namespace} exec ${pod} cilium status | grep "Cilium:" | grep -c 'OK' || true"
  local INFO_CMD="true"
  local MAX_MINS="2"
  local ERROR_OUTPUT="Timeout while waiting for Cilium to be ready"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
}

function wait_for_cilium_ep_gen {
  local NUM_DESIRED="0"
  local CMD="cilium endpoint list | grep -c regenerating"
  local INFO_CMD="true"
  local MAX_MINS="2"
  local ERROR_OUTPUT="Timeout while waiting for endpoints to regenerate"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
}

function wait_for_daemon_set_not_ready {
  set +x

  check_num_params "$#" "2"

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
  local NUM_DESIRED="0"
  local CMD="cilium endpoint list | grep -c Disabled"
  local INFO_CMD="true"
  local MAX_MINS="2"
  local ERROR_OUTPUT="Timeout while waiting for policy to be enabled for all endpoints"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
}

function count_lines_in_log {
    echo `wc -l $DUMP_FILE | awk '{ print $1 }'`
}

function wait_for_log_entries {
  set +x
  check_num_params "$#" "1"
  local expected=$(($1 + $(count_lines_in_log)))
  wait_specified_time_test "test \"\$(count_lines_in_log)\" -ge \"$expected\"" "2"
  set -x
}

function wait_for_docker_ipv6_addr {
  #set +x
  set -xv
  check_num_params "$#" "1"
  name=$1
  wait_specified_time_test "test \"\$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' $name)\" != \"\"" "2"
  set -x
}

function wait_for_running_pod {
  set +x
  pod=$1
  namespace=${2:-default}
  echo "Waiting for ${pod} pod to be Running..."
  wait_specified_time_test "test \"\$(kubectl get pods -n ${namespace} -o wide | grep ${pod} | grep -c Running)\" -eq \"1\"" "5"
  set -x
}

function wait_for_no_pods {
  #set +x
  set -xv
  namespace=${1:-default}
  echo "Waiting for no pods to be Running in namespace ${namespace}"
  wait_specified_time_test "test \"\$(kubectl get pods -n ${namespace} -o wide 2>&1 | grep -c 'No resources found')\" -eq \"1\"" "5"
  set -xv
}

function wait_for_n_running_pods {
  set +x
  check_num_params "$#" "1"
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
  local TEST_NAME=$1
  local TEST_SUITE=$2
  local CILIUM_ROOT="src/github.com/cilium/cilium"
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
  local RUN="/var/run/cilium"
  local LIB="/var/lib/cilium"
  local RUN_DIR="${CILIUM_DIR}${RUN}"
  local LIB_DIR="${CILIUM_DIR}${LIB}"
  mkdir -p ${CILIUM_DIR}
  mkdir -p ${RUN_DIR}
  mkdir -p ${LIB_DIR}
  if [[ "${TEST_SUITE}" == "runtime-tests" ]]; then
    local CLI_OUT_DIR="${CILIUM_DIR}/cli"
    mkdir -p ${CLI_OUT_DIR}
    dump_cli_output ${CLI_OUT_DIR} || true
  fi
  sudo cp -r ${RUN}/state ${RUN_DIR} || true
  sudo cp -r ${LIB}/* ${LIB_DIR} || true
  find ${CILIUM_DIR} -type d -exec sudo chmod 777 {} \;
  find ${CILIUM_DIR} -exec sudo chmod a+r {} \;
}

function dump_cli_output {
  check_num_params "$#" "1"
  local DIR=$1
  cilium endpoint list > ${DIR}/endpoint_list.txt
  local EPS=$(cilium endpoint list | tail -n+3 | awk '{print $1}' | grep -o '[0-9]*')
  for ep in ${EPS} ; do
    cilium endpoint get ${ep} > ${DIR}/endpoint_get_${ep}.txt
    cilium bpf policy list ${ep} > ${DIR}/bpf_policy_list_${ep}.txt
  done
  cilium service list > ${DIR}/service_list.txt
  local SVCS=$(cilium service list | tail -n+2 | awk '{print $1}')
  for svc in ${SVCS} ; do
    cilium service get ${svc} > ${DIR}/service_get_${svc}.txt
  done
  local IDS=$(cilium endpoint list | tail -n+3 | awk '{print $3}' | grep -o '[0-9]*')
  for id in ${IDS} ; do
    cilium identity get ${id} > ${DIR}/identity_get_${id}.txt
  done
  cilium config > ${DIR}/config.txt
  cilium bpf lb list > ${DIR}/bpf_lb_list.txt
  cilium bpf ct list global > ${DIR}/bpf_ct_list_global.txt
  cilium bpf tunnel list > ${DIR}/bpf_tunnel_list.txt
  cilium policy get > ${DIR}/policy_get.txt
  cilium status > ${DIR}/status.txt
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

  check_num_params "$#" "3"

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
  check_num_params "$#" "1"
  local namespace=$1
  local pods=$(kubectl -n $namespace get pods -l k8s-app=cilium | grep cilium- | awk '{print $1}')

  for pod in $pods; do
    wait_for_kubectl_cilium_status $namespace $pod
  done
}

function k8s_count_all_cluster_cilium_eps {
  local total=0
  check_num_params "$#" "1"
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
  wait_specified_time_test "test \$(kubectl get cs)" "10"
  set -x
}

function wait_for_service_endpoints_ready {
  set +x
  check_num_params "$#" "3"
  local namespace="${1}"
  local name="${2}"
  local port="${3}"

  echo "Waiting for ${name} service endpoints to be ready"
  wait_specified_time_test "test \"\$(kubectl get endpoints -n ${namespace} ${name} | grep -c \":${port}\")\" -eq \"1\"" "5"
  set -x
}

function k8s_apply_policy {
  declare -A currentRevison
  local i
  local pod
  check_num_params "$#" "3"
  local namespace=$1
  local action=$2
  local policy=$3
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

  kubectl $action -f $policy

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
  check_num_params "$#" "1"
  local VM_NAME=$1
  vagrant ssh-config ${VM_NAME} | grep IdentityFile | awk '{print $2}'
}

function get_vm_ssh_port {
  check_num_params "$#" "1"
  local VM_NAME=$1
  vagrant ssh-config ${VM_NAME} | grep Port | awk '{ print $2 }'
}

function copy_files_vm {
  check_num_params "$#" "2"
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
  check_num_params "$#" "1"
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
  check_num_params "$#" "1"
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
  check_num_params "$#" "1"
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
  check_num_params "$#" "2"
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

# diff_timeout waits for the output of the commands specified via $1 and $2 to
# be identical by comparing the output with `diff -Nru`. The commands are
# executed consecutively with a 2 second pause until the output matches or the
# timeout of 1 minute is reached.
function diff_timeout() {
  local arg1="$1"
  local arg2="$2"
  local sleep_time=2
  local iter=0
  local found="0"

  until [[ "$found" -eq "1" ]]; do
    if [[ $((iter++)) -gt $((30)) ]]; then
      echo "Timeout"
      abort "$DIFF"
    fi

    DIFF=$(diff -Nru <(eval "$arg1") <(eval "$arg2") || true)
    if [[ "$DIFF" == "" ]]; then
      found="1"
    else
      sleep $sleep_time
    fi
  done
}

#######################################
# Waits for MAX_MINS until the output of CMD
# reaches NUM_DESIRED. While the state is not
# realized, INFO_CMD is emitted. If the state
# is not realized after MAX_MINS, ERROR_OUTPUT
# is emitted.
# Globals: 
# Arguments:
#   NUM_DESIRED: desired number output by CMD.
#   CMD: command to run.
#   INFO_CMD: command to run while state is not
#             realized
#   MAX_MINS: maximum minutes to wait for desired
#             state
#   ERROR_OUTPUT: message that is emitted if desired
#                 state is not realized in MAX_MINS.
# Returns:
#   None
#######################################
function wait_for_desired_state {
  check_num_params "$#" "5"
  local NUM_DESIRED="$1"
  local CMD="$2"
  local INFO_CMD="$3"
  local MAX_MINS="$4"
  local ERROR_OUTPUT="$5"
  set +x
  local sleep_time=1
  local iter=0
  local found=$(eval "$CMD")
  echo "found: $found"

  while [[ "$found" -ne "$NUM_DESIRED" ]]; do
    if [[ $((iter++)) -gt $((${MAX_MINS}*60/$sleep_time)) ]]; then
      echo ""
      echo $ERROR_OUTPUT
      exit 1
    else
      eval "$INFO_CMD"
      echo -n " [$found/$NUM_DESIRED]"
      sleep $sleep_time
    fi
    found=$(eval "${CMD}")
    echo "found: $found"
  done
  set -x
  eval "${INFO_CMD}"
}

#######################################
# Waits for MAX_MINS until CMD returns with
# return code 0. If the desired state is
# not realized after MAX_MINS, exits with
# failure.
# Globals:
# Arguments:
#   CMD: command to run.
#   MAX_MINS: maximum minutes to wait for desired
#             state
# Returns:
#   None
#######################################
function wait_specified_time_test {
  local CMD="$1"
  local MAX_MINS="$2"

  local sleep_time=1
  local iter=0
  while [[ "${iter}" -lt $((${MAX_MINS}*60/$sleep_time)) ]]; do
    if eval "${CMD}" ; then
      break
    fi
    sleep ${sleep_time}
    iter=$((iter+1))
  done
  if [[ "${iter}" -ge $((${MAX_MINS}*60/$sleep_time)) ]]; then
    echo "Timeout ${MAX_MINS} minutes exceeded for command \"$CMD\", Exiting with failure."
    set -x
    exit 1
  fi
}
