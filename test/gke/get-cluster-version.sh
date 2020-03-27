#!/bin/bash

# get-cluster-version.sh prints the version of the selected cluster. It expects
# the file 'cluster-name' to be populated. That file is created in
# select-cluster.sh

set -e

CLUSTER_NAME=$(cat ./gke/cluster-name)
K8S_VERSION=$(gcloud container clusters list --zone $GKE_ZONE --filter "name:${CLUSTER_NAME}" | awk '{print $3}' | grep -v MASTER_VERSION | sed -E 's/([0-9]+\.[0-9]+)\..*/\1/')
echo -n ${K8S_VERSION}
