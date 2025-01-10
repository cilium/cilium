#!/usr/bin/env bash

CILIUM_FILES="cilium-files"
DUMP_FILE=$(mktemp)
MONITOR_PID=""
LAST_LOG_DATE=""
TEST_NET=cilium
GOPS="/home/vagrant/go/bin/gops"

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

# Prevent Fedora rules in raw table from affecting the test.
ip6tables -t raw -F 2> /dev/null || true

function log {
  local save=$-
  set +u
  check_num_params "$#" "1"
  message=$1
  local stack
  for (( i=${#FUNCNAME[@]}-1 ; i>0 ; i-- )) ; do
    if [[ "${stack}" == "" ]]; then
      stack="$(basename $0): ${FUNCNAME[i]}"
    else
      stack="$stack/${FUNCNAME[i]}"
    fi
  done
  echo "----- ${stack}: $message"
  restore_flag $save "u"
}

# Usage: overwrite $iter 'commands --option --foo bar "quoted args" '
# Executes the commands provided as parameters, moves the cursor back by the
# number of lines output by the command, then prints the output of the command.
# If $iter is zero, then the cursor is not moved; this is equivalent to
# 'shift; eval "$@"'.
function overwrite {
  local iter=$1
  shift

  local output=$(eval "$@")
  if [ ! -z $TERM ] && [ $iter -ne 0 ]; then
    local ERASER=$(tput cuu1 ; tput el)
    local n_lines=$(echo "$output" | wc -l)
    for i in $(seq 1 $n_lines); do
      echo -ne "$ERASER"
    done
  fi
  echo "$output"
}

function get_filename_without_extension {
  check_num_params "$#" "1"
  local file=$(basename $1)
  local filename="${file%.*}"
  echo $filename
}
# Note: if you call this, do not change the value of the debug flag - you will make the shell segmentation fault :) 
function redirect_debug_logs {
  check_num_params "$#" "1"
  local LOGS_DIR=$1
  mkdir -p ${LOGS_DIR}
  exec {BASH_XTRACEFD}>>${LOGS_DIR}/debug.txt
}

function monitor_start {
  local save=$-
  set +e
  log "starting monitor and dumping contents to $DUMP_FILE"
  cilium-dbg monitor -v $@ > $DUMP_FILE &
  MONITOR_PID=$!
  restore_flag $save "e"
}

function monitor_resume {
  local save=$-
  set +e
  log "resuming monitor and dumping contents to $DUMP_FILE"
  cilium-dbg monitor -v $@ >> $DUMP_FILE &
  MONITOR_PID=$!
  restore_flag $save "e"
}

function monitor_clear {
  local save=$-
  set +e
  log "clearing monitor"
  cp /dev/null $DUMP_FILE
  nstat > /dev/null
  restore_flag $save "e"
}

function monitor_dump {
  local save=$-
  set +e
  nstat
  cat $DUMP_FILE
  restore_flag $save "e"
}

function monitor_stop {
  local save=$-
  set +e
  if [ ! -z "$MONITOR_PID" ]; then
    kill $MONITOR_PID || true > /dev/null 2>&1
  fi
  restore_flag $save "e"
}

function logs_clear {
  LAST_LOG_DATE="$(date +'%F %T')"
}

function abort {
  set +e
  echo "------------------------------------------------------------------------"
  echo "                            Test Failed"
  echo "$*"
  echo ""
  echo "------------------------------------------------------------------------"

  if [ ! -z "$DEBUG" ]; then
    cilium-dbg status
    cilium-dbg endpoint list
    cilium-dbg policy get
    read -n 1 -p "Press any key to continue..."
  fi

  monitor_dump
  monitor_stop

  echo "------------------------------------------------------------------------"
  echo "                            Cilium logs (last 200 lines)"
  journalctl --no-pager --since "${LAST_LOG_DATE}" -u cilium | tail -n 200
  echo ""
  echo "------------------------------------------------------------------------"

  exit 1
}

function micro_sleep {
  sleep 0.5
}

function kafka_consumer_delay {
  # wait for kafka consumer to come up
  sleep 5
}

function to_services_delay {
  sleep 5
}

function restore_flag {
  check_num_params "$#" "2"
  local save=$1
  local flag=$2
  if [[ $save =~ $2 ]]; then
    set -$2
  fi
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
  local save=$-
  set +e
  check_num_params "$#" "1"
  local NUM_DESIRED="$1"
  local CMD="cilium-dbg endpoint list | grep -v -e \"not-ready\" -e \"reserved\" | grep ready -c || true"
  local INFO_CMD="cilium-dbg endpoint list"
  local MAX_MINS="2"
  local ERROR_OUTPUT="Timeout while waiting for $NUM_DESIRED endpoints"
  log "waiting for up to ${MAX_MINS} mins for ${NUM_DESIRED} endpoints to be in \"ready\" state"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
  log "done waiting for up to ${MAX_MINS} mins for ${NUM_DESIRED} endpoints to be in \"ready\" state"
  restore_flag $save "e"
}

function wait_for_endpoints_deletion {
  local save=$-
  set +e
  local NUM_DESIRED="2" # When no endpoints are present there should be two lines only.
  local CMD="cilium-dbg endpoint list | grep -v \"reserved\" | wc -l || true"
  local INFO_CMD="cilium-dbg endpoint list"
  local MAX_MINS="2"
  local ERROR_OUTPUT="Timeout while waiting for endpoint removal"
  log "waiting for up to ${MAX_MINS} mins for all endpoints to be removed"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
  log "done waiting"
  restore_flag $save "e"
}

function k8s_num_ready {
  local save=$-
  set +e
  local NAMESPACE=$1
  local CILIUM_POD=$2
  local FILTER=$3
  kubectl -n ${NAMESPACE} exec ${CILIUM_POD} -- cilium-dbg endpoint list | grep $FILTER | grep -v -e 'not-ready' -e 'reserved' | grep -c 'ready' || true
  restore_flag $save "e"
}

function wait_for_k8s_endpoints {
  local save=$-
  set +e
  check_num_params "$#" "4"
  local NAMESPACE=$1
  local CILIUM_POD=$2
  local NUM=$3
  local FILTER=$4
  log "Waiting for $NUM endpoints in namespace $NAMESPACE managed by $CILIUM_POD"

  # Wait some time for at least one endpoint to get into regenerating state
  # FIXME: Remove when this is reliable
  sleep 5

  local sleep_time=1
  local iter=0
  local found
  found=$(k8s_num_ready "${NAMESPACE}" "${CILIUM_POD}" "${FILTER}")
  log "found: $found"
  while [[ "$found" -ne "$NUM" ]]; do
    if [[ $iter -gt $((5*60/$sleep_time)) ]]; then
      echo ""
      log "Timeout while waiting for $NUM endpoints"
      restore_flag $save "e"
      exit 1
    else
      overwrite $iter '
        kubectl -n ${NAMESPACE} exec -- ${CILIUM_POD} cilium-dbg endpoint list
        echo -n " [${found}/${NUM}]"
      '
      sleep $sleep_time
    fi
    found=$(k8s_num_ready "${NAMESPACE}" "${CILIUM_POD}" "${FILTER}")
    log "found: $found"
    ((iter++))
  done

  overwrite $iter 'kubectl -n ${NAMESPACE} exec ${CILIUM_POD} -- cilium-dbg endpoint list'
  restore_flag $save "e"
}

function wait_for_cilium_status {
  local NUM_DESIRED="1"
  local CMD="cilium-dbg status | grep 'Cilium:' | grep -c OK || true"
  local INFO_CMD="true"
  local MAX_MINS="1"
  local ERROR_OUTPUT="Timeout while waiting for Cilium to be ready"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
}

function wait_for_kubectl_cilium_status {
  check_num_params "$#" "2"
  namespace=$1
  pod=$2
  local NUM_DESIRED="1"
  local CMD="kubectl -n ${namespace} exec ${pod} -- cilium-dbg status | grep "Cilium:" | grep -c 'OK' || true"
  local INFO_CMD="true"
  local MAX_MINS="2"
  local ERROR_OUTPUT="Timeout while waiting for Cilium to be ready"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
}

function wait_for_cilium_ep_gen {
  local save=$-
  set +e
  local MODE=$1

  local NAMESPACE
  local POD
  local CMD
  local INFO_CMD

  if [[ "$MODE" == "k8s" ]]; then
    # Only care about provided params if mode is K8s.
    check_num_params "$#" "3"
    log "mode is K8s"
    NAMESPACE=$2
    POD=$3
    CMD="kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg endpoint list | grep -c regenerat"
    INFO_CMD="kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg endpoint list"
  else
    CMD="cilium-dbg endpoint list | grep -c regenerat"
    INFO_CMD="cilium-dbg endpoint list"
  fi

  local NUM_DESIRED="0"
  local MAX_MINS="2"
  local ERROR_OUTPUT="Timeout while waiting for endpoints to regenerate"
  local sleep_time=1

  local iter=0
  local found
  found=$(eval "$CMD")

  while [[ "$found" -ne "$NUM_DESIRED" ]]; do
    log "$found endpoints are still regenerating; want $NUM_DESIRED"
    if [[ $((iter++)) -gt $((${MAX_MINS}*60/$sleep_time)) ]]; then
      echo ""
      log "${ERROR_OUTPUT}"
      exit 1
    else
      overwrite $iter '
        log "still within time limit for waiting for endpoints to be in 'ready' state; sleeping and checking again"
        log "output of ${INFO_CMD}"
        eval "$INFO_CMD"
        echo -n " [$found/$NUM_DESIRED]"
        log "sleeping for $sleep_time"
      '
      sleep $sleep_time
    fi
    log "evaluating $CMD"
    found=$(eval "${CMD}")
    log "found: $found"
  done
  set -e
  restore_flag $save "e"
}

function wait_for_daemon_set_not_ready {
  local save=$-
  set +e
  check_num_params "$#" "2"

  local namespace="${1}"
  local name="${2}"

  log "Waiting for instances of Cilium daemon $name in namespace $namespace to be clean up"

  local sleep_time=2
  local iter=0
  local found="0"
  until [[ "$found" -eq "1" ]]; do
    if [[ $iter -gt $((5*60/$sleep_time)) ]]; then
      echo ""
      log "Timeout while waiting for cilium agent to be clean up by kubernetes"
      print_k8s_cilium_logs
      exit 1
    else
      overwrite $iter 'kubectl -n ${namespace} get pods -o wide'
      sleep $sleep_time
    fi
    kubectl get pods -n ${namespace} | grep ${name} -q
    found=$?
    ((iter++))
  done

  overwrite $iter 'kubectl -n kube-system get pods -o wide'
  restore_flag $save "e"
}

function wait_for_policy_enforcement {
  check_num_params "$#" "1"
  local NUM_DESIRED="$1"
  local CMD="cilium-dbg endpoint list | grep -c Disabled"
  local INFO_CMD="cilium-dbg endpoint list"
  local MAX_MINS="2"
  local ERROR_OUTPUT="Timeout while waiting for policy to be enabled for all endpoints"
  wait_for_desired_state "$NUM_DESIRED" "$CMD" "$INFO_CMD" "$MAX_MINS" "$ERROR_OUTPUT"
}

function count_lines_in_log {
    echo `wc -l $DUMP_FILE | awk '{ print $1 }'`
}

function wait_for_log_entries {
  check_num_params "$#" "1"
  local expected=$(($1 + $(count_lines_in_log)))
  wait_specified_time_test "test \"\$(count_lines_in_log)\" -ge \"$expected\"" "2"
}

function wait_for_docker_ipv6_addr {
  check_num_params "$#" "1"
  name=$1
  wait_specified_time_test "test \"\$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' $name)\" != \"\"" "2"
}

function wait_for_running_pod {
  pod=$1
  namespace=${2:-default}
  log "Waiting for ${pod} pod to be Running..."
  wait_specified_time_test "test \"\$(kubectl get pods -n ${namespace} -o wide | grep ${pod} | grep -c Running)\" -eq \"1\"" "10"
}

function wait_for_no_pods {
  namespace=${1:-default}
  log "Waiting for no pods to be Running in namespace ${namespace}"
  wait_specified_time_test "test \"\$(kubectl get pods -n ${namespace} -o wide 2>&1 | grep -c 'No resources found')\" -eq \"1\"" "5"
}

function wait_for_n_running_pods {
  local save=$-
  set +e
  check_num_params "$#" "1"
  local NPODS=$1
  log "Waiting for $NPODS running pods"

  local sleep_time=1
  local iter=0
  local found
  found=$(kubectl get pod | grep Running -c || true)
  until [[ "$found" -eq "$NPODS" ]]; do
    if [[ $iter -gt $((5*60/$sleep_time)) ]]; then
      echo ""
      log "Timeout while waiting for $NPODS running pods"
      exit 1
    else
      overwrite $iter '
        kubectl get pod -o wide
        echo -n " [${found}/${NPODS}]"
      '
      sleep $sleep_time
    fi
    found=$(kubectl get pod | grep Running -c || true)
    ((iter++))
  done

  overwrite $iter 'kubectl get pod -o wide'
  restore_flag $save "e"
}

# Wait for healthy k8s cluster on $1 nodes
function wait_for_healthy_k8s_cluster {
  local save=$-
  set +e
  local NNODES=$1
  log "Waiting for healthy k8s cluster with $NNODES nodes"

  local sleep_time=2
  local iter=0
  local found
  found=$(kubectl get cs | grep -v "STATUS" | grep -c "Healthy")
  until [[ "$found" -eq "3" ]]; do
    if [[ $iter -gt $((1*60/$sleep_time)) ]]; then
      echo ""
      log "Timeout while waiting for healthy kubernetes cluster"
      exit 1
    else
      overwrite $iter '
        kubectl get cs
        log "K8S Components ready: [${found}/3]"
      '
      sleep $sleep_time
    fi
    found=$(kubectl get cs | grep -v "STATUS" | grep -c "Healthy")
    ((iter++))
  done
  overwrite $iter 'kubectl get cs'
  local iter=0
  local found
  found=$(kubectl get nodes | grep Ready -c)
  until [[ "$found" -eq "$NNODES" ]]; do
    if [[ $iter -gt $((1*60/$sleep_time)) ]]; then
      echo ""
      log "Timeout while waiting for all nodes to be Ready"
      exit 1
    else
      overwrite $iter '
        kubectl get nodes
        log "Nodes ready [${found}/${NNODES}]"
      '
      sleep $sleep_time
    fi
    found=$(kubectl get nodes | grep Ready -c)
    ((iter++))
  done
  restore_flag $save "e"
}

function k8s_nodes_policy_status {
  local save=$-
  set +e
  local sleep_time=2
  local NNODES=$1
  local policy_ns=$2
  local policy_name=$3
  local iter=0
  local nodes=$(kubectl get ciliumnetworkpolicies -n "${policy_ns}" "${policy_name}" -o go-template --template='{{len .status.nodes}}')
  until [[ "${nodes}" -eq "${NNODES}" ]]; do
    if [[ $iter -gt $((1*60/$sleep_time)) ]]; then
      echo ""
      log "Timeout while waiting for $NNODES to have policy ${policy_ns}/${policy_name} installed"
      exit 1
    else
      overwrite $iter '
        kubectl get nodes
        log "Nodes with policy accepted [${found}/${NNODES}]"
      '
      sleep $sleep_time
    fi
    found=$(kubectl get nodes | grep Ready -c)
    ((iter++))
  done

  kubectl get ciliumnetworkpolicies -n "${policy_ns}" "${policy_name}" -o go-template --template='{{.status.nodes}}'
  restore_flag $save "e"
}

function gather_files {
  local TEST_NAME=$1
  local TEST_SUITE=$2
  log "gathering files for test $TEST_NAME in test suite $TEST_SUITE"
  local CILIUM_ROOT="src/github.com/cilium/cilium"
  if [ -z "${TEST_SUITE}" ]; then
    TEST_SUITE="runtime-tests"
  fi
  if [ -z "${GOPATH}" ]; then
    local GOPATH="/home/vagrant/go"
  fi
  CILIUM_DIR="${GOPATH}/${CILIUM_ROOT}/test/envoy/cilium-files/${TEST_NAME}"
  local RUN="/var/run/cilium"
  local LIB="/var/lib/cilium"
  local RUN_DIR="${CILIUM_DIR}${RUN}"
  local LIB_DIR="${CILIUM_DIR}${LIB}"
  mkdir -p "${CILIUM_DIR}"
  mkdir -p "${RUN_DIR}"
  mkdir -p "${LIB_DIR}"
  if [[ "${TEST_SUITE}" == "runtime-tests" ]]; then
    local CLI_OUT_DIR="${CILIUM_DIR}/cli"
    local PROF_OUT_DIR="${CILIUM_DIR}/profiling"
    mkdir -p "${CLI_OUT_DIR}"
    dump_cli_output "${CLI_OUT_DIR}" || true
    dump_gops_output "${PROF_OUT_DIR}" "cilium-agent" || true
  else
    # Get logs from each Cilium pod.
    local NAMESPACE="kube-system"
    local CILIUM_POD_1=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | awk 'NR==2{ print $1 }')
    local CILIUM_POD_2=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | awk 'NR==3{ print $1 }')
    local CLI_OUT_DIR=${CILIUM_DIR}/cli
    mkdir -p "${CLI_OUT_DIR}"
    log "gathering Cilium logs from pod ${CILIUM_POD_1}"
    dump_cli_output_k8s "${CLI_OUT_DIR}" "${NAMESPACE}" "${CILIUM_POD_1}" || true
    log "gathering Cilium logs from pod ${CILIUM_POD_2}"
    dump_cli_output_k8s "${CLI_OUT_DIR}" "${NAMESPACE}" "${CILIUM_POD_2}" || true
  fi
  sudo cp -r ${RUN}/state "${RUN_DIR}" || true
  sudo cp ${RUN}/*.log "${RUN_DIR}" || true
  sudo cp -r ${LIB}/* "${LIB_DIR}" || true
  find "${CILIUM_DIR}" -type d -exec sudo chmod 777 {} \;
  find "${CILIUM_DIR}" -exec sudo chmod a+r {} \;
  log "finished gathering files for test $TEST_NAME in test suite $TEST_SUITE"
}

function dump_cli_output {
  check_num_params "$#" "1"
  local DIR=$1
  cilium-dbg endpoint list > ${DIR}/endpoint_list.txt
  local EPS=$(cilium-dbg endpoint list | tail -n+3 | grep '^[0-9]' | awk '{print $1}')
  for ep in ${EPS} ; do
    cilium-dbg endpoint get ${ep} > ${DIR}/endpoint_get_${ep}.txt
    cilium-dbg bpf policy get ${ep} > ${DIR}/bpf_policy_list_${ep}.txt
  done
  cilium-dbg service list > ${DIR}/service_list.txt
  local SVCS=$(cilium-dbg service list | tail -n+2 | awk '{print $1}')
  for svc in ${SVCS} ; do
    cilium-dbg service get ${svc} > ${DIR}/service_get_${svc}.txt
  done
  local IDS=$(cilium-dbg endpoint list | tail -n+3 | awk '{print $4}' | grep -o '[0-9]*')
  for id in ${IDS} ; do
    cilium-dbg identity get ${id} > ${DIR}/identity_get_${id}.txt
  done
  cilium-dbg config > ${DIR}/config.txt
  cilium-dbg bpf lb list > ${DIR}/bpf_lb_list.txt
  cilium-dbg bpf ct list global > ${DIR}/bpf_ct_list_global.txt
  cilium-dbg bpf tunnel list > ${DIR}/bpf_tunnel_list.txt
  cilium-dbg policy get > ${DIR}/policy_get.txt
  cilium-dbg status > ${DIR}/status.txt
  cilium-dbg debuginfo -f ${DIR}/debuginfo.txt
  cilium-bugtool -t ${DIR}
}

function dump_cli_output_k8s {
  check_num_params "$#" "3"
  local DIR=$1
  local NAMESPACE=$2
  local POD=$3
  kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg endpoint list > ${DIR}/${POD}_endpoint_list.txt
  local EPS=$(kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg endpoint list | tail -n+3 | grep '^[0-9]' | awk '{print $1}')
  for ep in ${EPS} ; do
    kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg endpoint get ${ep} > ${DIR}/${POD}_endpoint_get_${ep}.txt
    kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg bpf policy get ${ep} > ${DIR}/${POD}_bpf_policy_list_${ep}.txt
  done
  kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg service list > ${DIR}/${POD}_service_list.txt
  local SVCS=$(kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg service list | tail -n+2 | awk '{print $1}')
  for svc in ${SVCS} ; do
    kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg service get ${svc} > ${DIR}/${POD}_service_get_${svc}.txt
  done
  local IDS=$(kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg endpoint list | tail -n+3 | awk '{print $4}' | grep -o '[0-9]*')
  for id in ${IDS} ; do
    kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg identity get ${id} > ${DIR}/${POD}_identity_get_${id}.txt
  done
  kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg config > ${DIR}/${POD}_config.txt
  kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg bpf lb list > ${DIR}/${POD}_bpf_lb_list.txt
  kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg bpf ct list global > ${DIR}/${POD}_bpf_ct_list_global.txt
  kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg bpf tunnel list > ${DIR}/${POD}_bpf_tunnel_list.txt
  kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg policy get > ${DIR}/${POD}_policy_get.txt
  kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg status > ${DIR}/${POD}_status.txt
  kubectl exec -n ${NAMESPACE} ${POD} -- cilium-dbg debuginfo > ${DIR}/${POD}_debuginfo.txt
  local DEBUGTOOL_ARCHIVE=`kubectl exec -n ${NAMESPACE} ${POD} -- cilium-bugtool | grep ARCHIVE | awk '{ print $3}'`
  kubectl cp ${NAMESPACE}/${POD}:${DEBUGTOOL_ARCHIVE} ${DIR}/${POD}_bugtool.tar
}

function dump_gops_output {
  check_num_params "$#" "2"
  local DIR="$1"
  local PROG="$2"
  local PROG_PROFILING_DIR="${DIR}/${PROG}"
  mkdir -p "${PROG_PROFILING_DIR}"
  log "getting gops output for ${PROG} and dumping to dir ${PROG_PROFILING_DIR}"
  local PROG_PID=$(sudo ${GOPS} | grep "${PROG}" | awk '{print $1}')
  log "running \"gops stack\" for ${PROG}"
  sudo ${GOPS} stack ${PROG_PID} > "${PROG_PROFILING_DIR}/${PROG}_stack.txt"
  log "running \"gops memstats\" for ${PROG}"
  sudo ${GOPS} memstats ${PROG_PID} > "${PROG_PROFILING_DIR}/${PROG}_memstats.txt"
  log "running \"gops stats\" for ${PROG}"
  sudo ${GOPS} stats ${PROG_PID} > "${PROG_PROFILING_DIR}/${PROG}_stats.txt"
  log "done getting gops output for ${PROG}"
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
  local save=$-
  set +e
  check_num_params "$#" "3"

  local namespace="${1}"
  local name="${2}"
  local n_ds_expected="${3}"

  log "Waiting for $n_ds_expected instances of Cilium daemon $name in namespace $namespace to become ready"

  local sleep_time=2
  local iter=0
  local found="0"
  until [[ "$found" -eq "$n_ds_expected" ]]; do
    if [[ $iter -gt $((5*60/$sleep_time)) ]]; then
      echo ""
      log "Timeout while waiting for cilium-agent"
      print_k8s_cilium_logs
      exit 1
    else
      overwrite $iter '
        kubectl -n kube-system get ds
        kubectl -n kube-system get pods -o wide
        echo -n " [${found}/${n_ds_expected}]"
      '
      sleep $sleep_time
    fi
    found=$(kubectl get ds -n ${namespace} ${name} 2>&1 | awk 'NR==2{ print $4 }')
    ((iter++))
  done
  overwrite $iter 'kubectl -n kube-system get pods -o wide'
  restore_flag $save "e"
}

function k8s_wait_for_cilium_status_ready {
  local save=$-
  set +e
  local pod
  check_num_params "$#" "1"
  local namespace=$1
  local pods=$(kubectl -n $namespace get pods -l k8s-app=cilium | grep cilium- | awk '{print $1}')

  for pod in $pods; do
    wait_for_kubectl_cilium_status $namespace $pod
  done
  restore_flag $save "e"
}

function k8s_count_all_cluster_cilium_eps {
  local save=$-
  set +e
  local total=0
  check_num_params "$#" "1"
  local pod
  local namespace=$1
  local pods=$(kubectl -n $namespace get pods -l k8s-app=cilium | grep cilium- | awk '{print $1}')

  for pod in $pods; do
    local n_eps=$(kubectl -n $namespace exec $pod -- cilium-dbg endpoint list --no-headers | wc -l)
    total=$(( $total + $n_eps ))
  done

  echo "$total"
  restore_flag $save "e"
}

function wait_for_api_server_ready {
  log "Waiting for kube-apiserver to spin up"
  wait_specified_time_test "test \$(kubectl get cs)" "10"
}

function wait_for_service_endpoints_ready {
  check_num_params "$#" "3"
  local namespace="${1}"
  local name="${2}"
  local port="${3}"

  log "Waiting for ${name} service endpoints to be ready"
  wait_specified_time_test "test \"\$(kubectl get endpoints -n ${namespace} ${name} | grep -c \":${port}\")\" -eq \"1\"" "10"
  log "Done waiting for ${name} service endpoints to be ready"
  kubectl get endpoints -n ${namespace} ${name}
}

function wait_for_service_ready_cilium_pod {
  check_num_params "$#" "4"
  local namespace="${1}"
  local pod="${2}"
  local fe_port="${3}"
  # TODO: only works for one backend right now.
  local be_port="${4}"

  log "Waiting for Cilium pod ${pod} to have services ready with frontend port: ${fe_port} and backend port: ${be_port}"

  wait_specified_time_test "test \"\$(kubectl -n ${namespace} exec ${pod} -- cilium-dbg service list | awk '{ print \$2 }' | grep -c \":${fe_port}\")\" -ge \"1\"" "10"
  wait_specified_time_test "test \"\$(kubectl -n ${namespace} exec ${pod} -- cilium-dbg service list | awk '{ print \$5 }' | grep -c \":${be_port}\")\" -ge \"1\"" "10"

  log "Done waiting for Cilium pod ${pod} to have services ready with frontend port: ${fe_port} and backend port: ${be_port}"

  log "Listing all services:"
  kubectl -n ${namespace} exec ${pod} -- cilium-dbg service list
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
    local rev=$(kubectl -n $namespace exec $pod -- cilium-dbg policy get | grep Revision: | awk '{print $2}')
    currentRevison[$pod]=$rev
  done

  log "Current policy revisions:"
  for i in "${!currentRevison[@]}"
  do
    echo "  $i: ${currentRevison[$i]}"
  done

  kubectl $action -f $policy

  for pod in $pods; do
    local nextRev=$(expr ${currentRevison[$pod]} + 1)
    log "Waiting for agent $pod endpoints to get to revision $nextRev"
    timeout 180s kubectl -n $namespace exec $pod -- cilium-dbg policy wait $nextRev
  done

  # Adding sleep as workaround for l7 stresstests
  sleep 10s
}

function policy_delete_and_wait {
  log "deleting policy $* and waiting up to 120 seconds to complete"
  rev=$(cilium-dbg policy delete $* | grep Revision: | awk '{print $2}')
  timeout 120s cilium-dbg policy wait $rev
}

function policy_import_and_wait {
  log "importing policy $* and waiting up to 120 seconds to complete"
  rev=$(cilium-dbg policy import $* | grep Revision: | awk '{print $2}')
  timeout 120s cilium-dbg policy wait $rev
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
  local ID_FILE
  local PORT

  # Check that the VM is running before we try to gather logs from it.
  check_vm_running $VM_NAME

  log "getting the VM identity file for $VM_NAME"
  ID_FILE=$(get_vm_identity_file $VM_NAME)
  log "getting the port for $VM_NAME to SSH"
  PORT=$(get_vm_ssh_port $VM_NAME)

  log "getting cilium logs from $VM_NAME"
  vagrant ssh $VM_NAME -c 'sudo -E bash -c "journalctl --no-pager -u cilium > /home/vagrant/go/src/github.com/cilium/cilium/test/envoy/cilium-files/cilium-logs && chmod a+r /home/vagrant/go/src/github.com/cilium/cilium/test/envoy/cilium-files/cilium-logs"'
  vagrant ssh $VM_NAME -c 'sudo -E bash -c "journalctl --no-pager -u cilium-docker > /home/vagrant/go/src/github.com/cilium/cilium/test/envoy/cilium-files/cilium-docker-logs && chmod a+r /home/vagrant/go/src/github.com/cilium/cilium/test/envoy/cilium-files/cilium-docker-logs"'

  log "listing all logs that will be gathered from $VM_NAME"
  vagrant ssh $VM_NAME -c 'ls -altr /home/vagrant/go/src/github.com/cilium/cilium/test/envoy/cilium-files'

  log "copying logs from $VM_NAME onto VM host for accessibility after VM is destroyed"
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
  if [ ! -z "${K8STAG}" ] ; then
    local K8S_TAG="${K8STAG:-k8s}"
  fi

  if [ ! -z "${BUILD_NUMBER}" ] ; then
    local BUILD_ID_NAME="-build-${BUILD_ID}"
  fi

  echo "cilium${K8S_TAG}-master${BUILD_ID_NAME}"
}

function check_vm_running {
  check_num_params "$#" "1"
  local VM=$1
  log "getting status of VM ${VM}"
  vagrant status ${VM}
  log "done getting status of VM ${VM}"

  local VM_STATUS
  VM_STATUS=`vagrant status ${VM} | grep ${VM} | awk '{print $2}'`
  if [[ "${VM_STATUS}" != "running" ]]; then
    log "$VM is not in \"running\" state; exiting"
  else
    log "$VM is \"running\" continuing"
  fi
}

function wait_for_agent_socket {
  check_num_params "$#" "1"
  MAX_WAIT=$1

  log "waiting at most ${MAX_WAIT} iterations for cilium agent socket"
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

  log "waiting at most ${MAX_WAIT} iterations for PID ${TARGET_PID} to be killed"
  local i=0

  while [ $i -lt "${MAX_WAIT}" ]; do
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
  local save=$-
  set +e
  local arg1="$1"
  local arg2="$2"
  local sleep_time=2
  local iter=0
  local found="0"

  until [[ "$found" -eq "1" ]]; do
    if [[ $((iter++)) -gt $((30)) ]]; then
      log "Timeout waiting for diff to be empty"
      abort "$DIFF"
    fi

    DIFF=$(diff -Nru <(eval "$arg1") <(eval "$arg2") || true)
    if [[ "$DIFF" == "" ]]; then
      found="1"
    else
      sleep $sleep_time
    fi
  done
  restore_flag $save "e"
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

  local save=$-
  set +e
  check_num_params "$#" "5"
  local NUM_DESIRED="$1"
  local CMD="$2"
  local INFO_CMD="$3"
  local MAX_MINS="$4"
  local ERROR_OUTPUT="$5"
  local sleep_time=1
  local iter=0
  local found
  found=$(eval "$CMD")
  log "waiting for at most ${MAX_MINS} minutes for command ${CMD} to succeed"
  log "found: $found"

  while [[ "$found" -ne "$NUM_DESIRED" ]]; do
    if [[ $iter -gt $((${MAX_MINS}*60/$sleep_time)) ]]; then
      echo ""
      log "$ERROR_OUTPUT"
      exit 1
    else
      overwrite $iter '
        log "desired state not realized; will sleep and try again"
        eval "$INFO_CMD"
        echo -n " [$found/$NUM_DESIRED]"
      '
      sleep $sleep_time
    fi
    found=$(eval "${CMD}")
    log "found: $found"
    ((iter++))
  done
  log "desired state realized for command ${CMD}"
  eval "${INFO_CMD}"
  restore_flag $save "e"
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
  local save=$-
  set +e
  local CMD="$1"
  local MAX_MINS="$2"

  local sleep_time=1
  local iter=0

  log "waiting for at most ${MAX_MINS} minutes for command ${CMD} to succeed"
  while [[ "${iter}" -lt $((${MAX_MINS}*60/$sleep_time)) ]]; do
    if eval "${CMD}" ; then
      log "${CMD} succeeded"
      break
    fi
    overwrite $iter '
      log "${iter} < $((${MAX_MINS}*60/$sleep_time)) "
      log "${CMD} did not succeed; sleeping and testing the command again"
    '
    sleep ${sleep_time}
    iter=$((iter+1))
  done
  if [[ "${iter}" -ge $((${MAX_MINS}*60/$sleep_time)) ]]; then
    log "Timeout ${MAX_MINS} minutes exceeded for command \"$CMD\""
    log "Exiting with failure."
    exit 1
  fi
  log "${CMD} succeeded"
  restore_flag $save "e"
}

function create_cilium_docker_network {
  log "creating Docker network of type Cilium"
  docker network inspect $TEST_NET 2> /dev/null || {
    docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
  }
}

function remove_cilium_docker_network {
  local save=$-
  set +e
  log "removing Docker network of type cilium"
  docker network rm $TEST_NET > /dev/null 2>&1 
  restore_flag $save "e"
}

function test_succeeded {
  check_num_params "$#" "1"
  local TEST_NAME="$1"
  echo "============================================================"
  echo "==                                                        =="
  echo "==                                                        =="
  echo "==                                                        =="
  echo "    ${TEST_NAME} succeeded!"
  echo "==                                                        =="
  echo "==                                                        =="
  echo "==                                                        =="
  echo "============================================================"
}

function ping_fail {
  check_num_params "$#" "2"
  C1=$1
  C2=$2
  log "pinging $C2 from $C1 (expecting failure) "
  docker exec -i  ${C1} bash -c "ping -c 5 ${C2}" && {
      abort "Error: Unexpected success pinging ${C2} from ${C1}"
  }
}

function ping_success {
  check_num_params "$#" "2"
  C1=$1
  C2=$2
  log "pinging $C2 from $C1 (expecting success) "
  docker exec -i ${C1} bash -c "ping -c 5 ${C2}" || {
    abort "Error: Could not ping ${C2} from ${C1}"
  }
}

function wait_for_cilium_shutdown {
  local save=$-
  set +e
  log "waiting for cilium to shutdown"
  i=0
  while pgrep cilium-agent; do
    micro_sleep
    if [[ ${i} -ge 240 ]]; then
      log "Timeout while waiting for Cilium to shutdown"
      exit 1
    fi
    ((i++))
  done
  log "finished waiting for cilium to shutdown"
  restore_flag $save "e"
}
