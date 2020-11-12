#!/bin/bash

# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

# this script sets management cluster nodepool cnrm object nodecount and resizes the cluster via gcloud cli

if [ ! "$#" -eq 2 ] ; then
  echo "$0 supports exactly 2 arguments - desired node count and cluster uri"
  exit 1
fi

project="cilium-ci"
# this is only needs to be set as some of gcloud commands requires it,
# but as this script uses resource URIs clusters in all locations are
# going to be discovered and used
region="us-west1"

node_count=${1}
cluster_uri=${2}
cluster_name=${cluster_uri##*/}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export KUBECONFIG="${script_dir}/resize-kubeconfig"
gcloud container clusters get-credentials --project "${project}" --region "europe-west4" management-cluster-0

kubectl get containernodepools.container.cnrm.cloud.google.com ${cluster_name} -n test-clusters -o yaml | sed "s/nodeCount:.*$/nodeCount: ${node_count}/g" | kubectl replace -f -

gcloud container clusters get-credentials --project "${project}" --region "${region}" "${cluster_uri}"

node_pools=($(gcloud container node-pools list --project "${project}" --region "${region}" --cluster "${cluster_uri}" --format="value(name)"))
if [ "${#node_pools[@]}" -ne 1 ] ; then
  echo "expected 1 node pool, found ${#node_pools[@]}"
  exit 1
fi

gcloud container clusters resize --project "${project}" --region "${region}" --node-pool "${node_pools[0]}" --num-nodes ${node_count} --quiet "${cluster_uri}"
