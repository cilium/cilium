#!/bin/bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Call this to dump all master and node logs into the folder specified in $1
# (defaults to _artifacts). Only works if the provider supports SSH.

# TODO(shyamjvs): This script should be moved to test/e2e which is where it ideally belongs.
set -o errexit
set -o nounset
set -o pipefail

readonly report_dir="${1:-_artifacts}"
readonly gcs_artifacts_dir="${2:-}"
readonly logexporter_namespace="${3:-logexporter}"

# In order to more trivially extend log-dump for custom deployments,
# check for a function named log_dump_custom_get_instances. If it's
# defined, we assume the function can me called with one argument, the
# role, which is either "master" or "node".
echo "Checking for custom logdump instances, if any"
if [[ $(type -t log_dump_custom_get_instances) == "function" ]]; then
  readonly use_custom_instance_list=yes
else
  readonly use_custom_instance_list=
fi

readonly master_ssh_supported_providers="gce aws"
readonly node_ssh_supported_providers="gce gke aws"
readonly gcloud_supported_providers="gce gke"

readonly master_logfiles="kube-apiserver kube-scheduler rescheduler kube-controller-manager etcd etcd-events glbc cluster-autoscaler kube-addon-manager fluentd"
readonly node_logfiles="kube-proxy fluentd node-problem-detector"
readonly node_systemd_services="node-problem-detector"
readonly hollow_node_logfiles="kubelet-hollow-node-* kubeproxy-hollow-node-* npd-hollow-node-*"
readonly aws_logfiles="cloud-init-output"
readonly gce_logfiles="startupscript"
readonly kern_logfile="kern"
readonly initd_logfiles="docker"
readonly supervisord_logfiles="kubelet supervisor/supervisord supervisor/kubelet-stdout supervisor/kubelet-stderr supervisor/docker-stdout supervisor/docker-stderr"
readonly systemd_services="kubelet docker"

# Limit the number of concurrent node connections so that we don't run out of
# file descriptors for large clusters.
readonly max_scp_processes=25

function setup() {
  if [[ -z "${use_custom_instance_list}" ]]; then
    KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../..
    : ${KUBE_CONFIG_FILE:="config-test.sh"}
    echo "Sourcing kube-util.sh"
    source "${KUBE_ROOT}/cluster/kube-util.sh"
    echo "Detecting project"
    detect-project 2>&1
  elif [[ "${KUBERNETES_PROVIDER}" == "gke" ]]; then
    echo "Using 'use_custom_instance_list' with gke, skipping check for LOG_DUMP_SSH_KEY and LOG_DUMP_SSH_USER"
  elif [[ -z "${LOG_DUMP_SSH_KEY:-}" ]]; then
    echo "LOG_DUMP_SSH_KEY not set, but required when using log_dump_custom_get_instances"
    exit 1
  elif [[ -z "${LOG_DUMP_SSH_USER:-}" ]]; then
    echo "LOG_DUMP_SSH_USER not set, but required when using log_dump_custom_get_instances"
    exit 1
  fi
}

function log-dump-ssh() {
  if [[ -z "${use_custom_instance_list}" ]]; then
    ssh-to-node "$@"
    return
  fi

  local host="$1"
  local cmd="$2"

  ssh -oLogLevel=quiet -oConnectTimeout=30 -oStrictHostKeyChecking=no -i "${LOG_DUMP_SSH_KEY}" "${LOG_DUMP_SSH_USER}@${host}" "${cmd}"
}

# Copy all files /var/log/{$3}.log on node $1 into local dir $2.
# $3 should be a space-separated string of files.
# This function shouldn't ever trigger errexit, but doesn't block stderr.
function copy-logs-from-node() {
    local -r node="${1}"
    local -r dir="${2}"
    local files=( ${3} )
    # Append ".log*"
    # The * at the end is needed to also copy rotated logs (which happens
    # in large clusters and long runs).
    files=( "${files[@]/%/.log*}" )
    # Prepend "/var/log/"
    files=( "${files[@]/#/\/var\/log\/}" )
    # Comma delimit (even the singleton, or scp does the wrong thing), surround by braces.
    local -r scp_files="{$(printf "%s," "${files[@]}")}"

    if [[ "${gcloud_supported_providers}" =~ "${KUBERNETES_PROVIDER}" ]]; then
      # get-serial-port-output lets you ask for ports 1-4, but currently (11/21/2016) only port 1 contains useful information
      gcloud compute instances get-serial-port-output --project "${PROJECT}" --zone "${ZONE}" --port 1 "${node}" > "${dir}/serial-1.log" || true
      gcloud compute scp --recurse --project "${PROJECT}" --zone "${ZONE}" "${node}:${scp_files}" "${dir}" > /dev/null || true
    elif  [[ "${KUBERNETES_PROVIDER}" == "aws" ]]; then
      local ip=$(get_ssh_hostname "${node}")
      scp -oLogLevel=quiet -oConnectTimeout=30 -oStrictHostKeyChecking=no -i "${AWS_SSH_KEY}" "${SSH_USER}@${ip}:${scp_files}" "${dir}" > /dev/null || true
    elif  [[ -n "${use_custom_instance_list}" ]]; then
      scp -oLogLevel=quiet -oConnectTimeout=30 -oStrictHostKeyChecking=no -i "${LOG_DUMP_SSH_KEY}" "${LOG_DUMP_SSH_USER}@${node}:${scp_files}" "${dir}" > /dev/null || true
    else
      echo "Unknown cloud-provider '${KUBERNETES_PROVIDER}' and use_custom_instance_list is unset too - skipping logdump for '${node}'"
    fi
}

# Save logs for node $1 into directory $2. Pass in any non-common files in $3.
# Pass in any non-common systemd services in $4.
# $3 and $4 should be a space-separated list of files.
# Set $5 to true to indicate it is on master. Default to false.
# This function shouldn't ever trigger errexit
function save-logs() {
    local -r node_name="${1}"
    local -r dir="${2}"
    local files="${3}"
    local opt_systemd_services="${4:-""}"
    local on_master="${5:-"false"}"

    if [[ -n "${use_custom_instance_list}" ]]; then
      if [[ -n "${LOG_DUMP_SAVE_LOGS:-}" ]]; then
        files="${files} ${LOG_DUMP_SAVE_LOGS:-}"
      fi
    else
      case "${KUBERNETES_PROVIDER}" in
        gce|gke)
          files="${files} ${gce_logfiles}"
          ;;
        aws)
          files="${files} ${aws_logfiles}"
          ;;
      esac
    fi
    local -r services=( ${systemd_services} ${opt_systemd_services} ${LOG_DUMP_SAVE_SERVICES:-} )

    if log-dump-ssh "${node_name}" "command -v journalctl" &> /dev/null; then
        if [[ "${on_master}" == "true" ]]; then
          log-dump-ssh "${node_name}" "sudo journalctl --output=short-precise -u kube-master-installation.service" > "${dir}/kube-master-installation.log" || true
          log-dump-ssh "${node_name}" "sudo journalctl --output=short-precise -u kube-master-configuration.service" > "${dir}/kube-master-configuration.log" || true
        else
          log-dump-ssh "${node_name}" "sudo journalctl --output=short-precise -u kube-node-installation.service" > "${dir}/kube-node-installation.log" || true
          log-dump-ssh "${node_name}" "sudo journalctl --output=short-precise -u kube-node-configuration.service" > "${dir}/kube-node-configuration.log" || true
        fi
        log-dump-ssh "${node_name}" "sudo journalctl --output=short-precise -k" > "${dir}/kern.log" || true

        for svc in "${services[@]}"; do
            log-dump-ssh "${node_name}" "sudo journalctl --output=cat -u ${svc}.service" > "${dir}/${svc}.log" || true
        done
    else
        files="${kern_logfile} ${files} ${initd_logfiles} ${supervisord_logfiles}"
    fi

    echo "Changing logfiles to be world-readable for download"
    log-dump-ssh "${node_name}" "sudo chmod -R a+r /var/log" || true

    echo "Copying '${files}' from ${node_name}"
    copy-logs-from-node "${node_name}" "${dir}" "${files}"
}

function dump_masters() {
  local master_names
  if [[ -n "${use_custom_instance_list}" ]]; then
    master_names=( $(log_dump_custom_get_instances master) )
  elif [[ ! "${master_ssh_supported_providers}" =~ "${KUBERNETES_PROVIDER}" ]]; then
    echo "Master SSH not supported for ${KUBERNETES_PROVIDER}"
    return
  elif [[ -n "${KUBEMARK_MASTER_NAME:-}" ]]; then
    master_names=( "${KUBEMARK_MASTER_NAME}" )
  else
    if ! (detect-master); then
      echo "Master not detected. Is the cluster up?"
      return
    fi
    master_names=( "${MASTER_NAME}" )
  fi

  if [[ "${#master_names[@]}" == 0 ]]; then
    echo "No masters found?"
    return
  fi

  proc=${max_scp_processes}
  for master_name in "${master_names[@]}"; do
    master_dir="${report_dir}/${master_name}"
    mkdir -p "${master_dir}"
    save-logs "${master_name}" "${master_dir}" "${master_logfiles}" "" "true" &

    # We don't want to run more than ${max_scp_processes} at a time, so
    # wait once we hit that many nodes. This isn't ideal, since one might
    # take much longer than the others, but it should help.
    proc=$((proc - 1))
    if [[ proc -eq 0 ]]; then
      proc=${max_scp_processes}
      wait
    fi
  done
  # Wait for any remaining processes.
  if [[ proc -gt 0 && proc -lt ${max_scp_processes} ]]; then
    wait
  fi
}

function dump_nodes() {
  local node_names
  if [[ -n "${1:-}" ]]; then
    echo "Dumping logs for nodes provided as args to dump_nodes() function"
    node_names=( "$@" )
  elif [[ -n "${use_custom_instance_list}" ]]; then
    echo "Dumping logs for nodes provided by log_dump_custom_get_instances() function"
    node_names=( $(log_dump_custom_get_instances node) )
  elif [[ ! "${node_ssh_supported_providers}" =~ "${KUBERNETES_PROVIDER}" ]]; then
    echo "Node SSH not supported for ${KUBERNETES_PROVIDER}"
    return
  else
    echo "Detecting nodes in the cluster"
    detect-node-names &> /dev/null
    node_names=( "${NODE_NAMES[@]}" )
  fi

  if [[ "${#node_names[@]}" == 0 ]]; then
    echo "No nodes found!"
    return
  fi

  node_logfiles_all="${node_logfiles}"
  if [[ "${ENABLE_HOLLOW_NODE_LOGS:-}" == "true" ]]; then
    node_logfiles_all="${node_logfiles_all} ${hollow_node_logfiles}"
  fi

  nodes_selected_for_logs=()
  if [[ -n "${LOGDUMP_ONLY_N_RANDOM_NODES:-}" ]]; then
    # We randomly choose 'LOGDUMP_ONLY_N_RANDOM_NODES' many nodes for fetching logs.
    for index in `shuf -i 0-$(( ${#node_names[*]} - 1 )) -n ${LOGDUMP_ONLY_N_RANDOM_NODES}`
    do
      nodes_selected_for_logs+=("${node_names[$index]}")
    done
  else
    nodes_selected_for_logs=( "${node_names[@]}" )
  fi

  proc=${max_scp_processes}
  for node_name in "${nodes_selected_for_logs[@]}"; do
    node_dir="${report_dir}/${node_name}"
    mkdir -p "${node_dir}"
    # Save logs in the background. This speeds up things when there are
    # many nodes.
    save-logs "${node_name}" "${node_dir}" "${node_logfiles_all}" "${node_systemd_services}" &

    # We don't want to run more than ${max_scp_processes} at a time, so
    # wait once we hit that many nodes. This isn't ideal, since one might
    # take much longer than the others, but it should help.
    proc=$((proc - 1))
    if [[ proc -eq 0 ]]; then
      proc=${max_scp_processes}
      wait
    fi
  done
  # Wait for any remaining processes.
  if [[ proc -gt 0 && proc -lt ${max_scp_processes} ]]; then
    wait
  fi
}

function dump_nodes_with_logexporter() {
  echo "Detecting nodes in the cluster"
  detect-node-names &> /dev/null

  if [[ "${#NODE_NAMES[@]}" == 0 ]]; then
    echo "No nodes found!"
    return
  fi

  # Obtain parameters required by logexporter.
  local -r service_account_credentials="$(cat ${GOOGLE_APPLICATION_CREDENTIALS} | base64 | tr -d '\n')"
  local -r cloud_provider="${KUBERNETES_PROVIDER}"
  local -r enable_hollow_node_logs="${ENABLE_HOLLOW_NODE_LOGS:-false}"
  local -r logexport_sleep_seconds="$(( 90 + NUM_NODES / 5 ))"

  # Fill in the parameters in the logexporter daemonset template.
  sed -i'' -e "s@{{.LogexporterNamespace}}@${logexporter_namespace}@g" "${KUBE_ROOT}/cluster/log-dump/logexporter-daemonset.yaml"
  sed -i'' -e "s@{{.ServiceAccountCredentials}}@${service_account_credentials}@g" "${KUBE_ROOT}/cluster/log-dump/logexporter-daemonset.yaml"
  sed -i'' -e "s@{{.CloudProvider}}@${cloud_provider}@g" "${KUBE_ROOT}/cluster/log-dump/logexporter-daemonset.yaml"
  sed -i'' -e "s@{{.GCSPath}}@${gcs_artifacts_dir}@g" "${KUBE_ROOT}/cluster/log-dump/logexporter-daemonset.yaml"
  sed -i'' -e "s@{{.EnableHollowNodeLogs}}@${enable_hollow_node_logs}@g" "${KUBE_ROOT}/cluster/log-dump/logexporter-daemonset.yaml"

  # Create the logexporter namespace, service-account secret and the logexporter daemonset within that namespace.
  KUBECTL="${KUBE_ROOT}/cluster/kubectl.sh"
  if ! "${KUBECTL}" create -f "${KUBE_ROOT}/cluster/log-dump/logexporter-daemonset.yaml"; then
    echo "Failed to create logexporter daemonset.. falling back to logdump through SSH"
    "${KUBECTL}" delete namespace "${logexporter_namespace}" || true
    dump_nodes "${NODE_NAMES[@]}"
    return
  fi

  # Give some time for the pods to finish uploading logs.
  sleep "${logexport_sleep_seconds}"

  # List registry of marker files (of nodes whose logexporter succeeded) from GCS.
  local nodes_succeeded
  for retry in {1..10}; do
    if nodes_succeeded=$(gsutil ls ${gcs_artifacts_dir}/logexported-nodes-registry); then
      echo "Successfully listed marker files for successful nodes"
      break
    else
      echo "Attempt ${retry} failed to list marker files for succeessful nodes"
      if [[ "${retry}" == 10 ]]; then
        echo "Final attempt to list marker files failed.. falling back to logdump through SSH"
        "${KUBECTL}" delete namespace "${logexporter_namespace}" || true
        dump_nodes "${NODE_NAMES[@]}"
        return
      fi
      sleep 2
    fi
  done

  # Collect names of nodes which didn't run logexporter successfully.
  # Note: This step is O(#nodes^2) as we check if each node is present in the list of succeeded nodes.
  # Making it linear would add code complexity without much benefit (as it just takes ~1s for 5k nodes).
  failed_nodes=()
  for node in "${NODE_NAMES[@]}"; do
    if [[ ! "${nodes_succeeded}" =~ "${node}" ]]; then
      echo "Logexporter didn't succeed on node ${node}. Queuing it for logdump through SSH."
      failed_nodes+=("${node}")
    fi
  done

  # Delete the logexporter resources and dump logs for the failed nodes (if any) through SSH.
  "${KUBECTL}" delete namespace "${logexporter_namespace}" || true
  if [[ "${#failed_nodes[@]}" != 0 ]]; then
    echo -e "Dumping logs through SSH for the following nodes:\n${failed_nodes[@]}"
    dump_nodes "${failed_nodes[@]}"
  fi
}

function main() {
  setup
  # Copy master logs to artifacts dir locally (through SSH).
  echo "Dumping logs from master locally to '${report_dir}'"
  dump_masters
  if [[ "${DUMP_ONLY_MASTER_LOGS:-}" == "true" ]]; then
    echo "Skipping dumping of node logs"
    return
  fi

  # Copy logs from nodes to GCS directly or to artifacts dir locally (through SSH).
  if [[ -n "${gcs_artifacts_dir}" ]]; then
    echo "Dumping logs from nodes to GCS directly at '${gcs_artifacts_dir}' using logexporter"
    dump_nodes_with_logexporter
  else
    echo "Dumping logs from nodes locally to '${report_dir}'"
    dump_nodes
  fi
}

main
