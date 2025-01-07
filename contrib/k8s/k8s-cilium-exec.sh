#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Usage Summary:
# This script is used to execute commands on Cilium pods running in a Kubernetes cluster.
#
# Features:
# 1. By default, executes the given command on all Cilium pods.
# 2. Supports an optional `-e` flag to allow explicit selection of a specific pod or all pods.
#
# Usage:
# ./k8s-cilium-exec.sh [-e] <command>
#   -e: Enables explicit selection mode, prompting the user to select a specific pod or all pods.
#   <command>: The command to be executed on the selected pod(s).
#
# Example:
# ./k8s-cilium-exec.sh -e cilium status

trap cleanup EXIT

function kill_jobs {
	j=$(jobs -p)
	if [ ! -z "$j" ]; then
		kill -$1 $j 2> /dev/null
	fi
}

function cleanup {
	kill_jobs INT
	sleep 2s
	kill_jobs TERM
}

function get_cilium_pods {
    kubectl -n "${K8S_NAMESPACE}" get pods -l k8s-app=cilium -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName
}

function execute_on_all_pods {
    echo ""
    echo "Executing command on all Cilium pods..."
    while read -r podName nodeName ; do
        (
            title="==== Detail from pod $podName, on node $nodeName ===="
            msg=$(kubectl -n "${K8S_NAMESPACE}" exec -c "${CONTAINER}" "${podName}" -- "${@}" 2>&1)
            echo -e "$title\n$msg\n"
        )&
    done <<< "$pods_list"
    wait
}

K8S_NAMESPACE="${K8S_NAMESPACE:-kube-system}"
CONTAINER="${CONTAINER:-cilium-agent}"

# Parse command line arguments
explicit_selection=false
while getopts ":e" opt; do
  case $opt in
    e)
      explicit_selection=true
      ;;
    *)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done
shift $((OPTIND - 1))

# Get the list of Cilium pods
pods_list=$(get_cilium_pods)

# Exit if no pods found
if [ -z "$pods_list" ] || [ "$pods_list" == "NAME   NODE" ]; then
    echo "No Cilium pods found. Exiting."
    exit 1
fi

# Remove the header row from pods_list
pods_list=$(echo "$pods_list" | tail -n +2)

# If explicit selection (-e) is provided
if [ "$explicit_selection" = true ]; then
    # Format pods with numeric indexing
    indexed_pods=()
    echo "Available Cilium pods:"
    index=1
    while read -r podName nodeName; do
        echo "$index. $podName   $nodeName"
        indexed_pods+=("$podName $nodeName")
        ((index++))
    done <<< "$pods_list"

    echo ""
    echo "Do you want to execute the command on a specific pod or (a) all pods?"
    read -rp "Enter your choice (pod number or a): " choice

    if [[ "$choice" =~ ^[0-9]+$ ]]; then
        selected_index=$((choice - 1))
        if [ "$selected_index" -ge 0 ] && [ "$selected_index" -lt "${#indexed_pods[@]}" ]; then
            selected_row="${indexed_pods[$selected_index]}"
            selected_pod_node=( $selected_row )
            echo ""
            title="==== Detail from pod ${selected_pod_node[0]} on node ${selected_pod_node[1]} ===="
            msg=$(kubectl -n "${K8S_NAMESPACE}" exec -c "${CONTAINER}" "${selected_pod_node[0]}" -- "${@}" 2>&1)
            echo -e "$title\n$msg\n"
        else
            echo "Invalid pod number. Exiting."
            exit 1
        fi

    elif [ "$choice" == "a" ]; then
        execute_on_all_pods "$@"
    else
        echo "Invalid choice. Exiting."
        exit 1
    fi
else
    # Default behavior: execute command on all pods
    execute_on_all_pods "$@"
fi

