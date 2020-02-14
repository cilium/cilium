#!/bin/bash

set -e

export KUBECONFIG=gke-kubeconfig

cluster=$(cat cluster-name)
echo "scaling $cluster ng to 0"
yes | gcloud container clusters resize $cluster --node-pool default-pool --num-nodes 0 --zone $GKE_ZONE

echo "releasing cluster lock from $cluster"
kubectl annotate deployment lock lock-

rm cluster-name
