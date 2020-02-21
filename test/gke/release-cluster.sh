#!/bin/bash

export KUBECONFIG=gke-kubeconfig

echo "deleting terminating namespaces"
./delete-terminating-namespaces.sh

set -e

cluster=$(cat cluster-name)
echo "scaling $cluster ng to 0"
yes | gcloud container clusters resize $cluster --node-pool default-pool --num-nodes 0 --zone $GKE_ZONE

echo "releasing cluster lock from $cluster"
kubectl annotate deployment lock lock-

rm cluster-name
