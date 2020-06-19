#!/bin/bash

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export KUBECONFIG="${script_dir}/gke-kubeconfig"
cluster_uri="$(cat "${script_dir}/cluster-uri")"

# Create a function to unlock the cluster. We then execute this on script exit.
# This should occur even if the script is interrupted, by a jenkins timeout,
# for example.
unlock() {    
    echo "releasing cluster lock from ${cluster_uri}"
    kubectl annotate deployment -n cilium-ci-lock lock lock-
}
trap unlock EXIT

echo "cleaning cluster after tests"
./clean-cluster.sh

set -e

echo "scaling ${cluster_uri} to 0"
${script_dir}/resize-cluster.sh 0 ${cluster_uri}

rm -f "${script_dir}/cluster-uri" "${script_dir}/cluster-name" "${script_dir}/cluster-version"
