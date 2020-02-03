#!/bin/bash

# get-cluster-version.sh prints the version of the selected cluster. It expects
# the file 'cluster-name' to be populated. That file is created in
# select-cluster.sh

set -e

zone=europe-west4-a
export KUBECONFIG=gke-kubeconfig


CLUSTER_NAME=$(cat cluster-name)
K8S_VERSION=$(gcloud container clusters list --filter "name:${CLUSTER_NAME}" | awk '{print $3}' | grep -v MASTER_VERSION | sed -E 's/([0-9]+\.[0-9]+)\..*/\1/'
echo ${K8S_VERSION}
