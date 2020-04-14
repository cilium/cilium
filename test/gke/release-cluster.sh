#!/bin/bash

export KUBECONFIG=gke-kubeconfig

# We leak istio pods for an unknown reason (these tests do cleanup). This may
# be related to timeouts or other failures. In any case, we delete them here to
# be sure.
echo "deleting istio-system namespace and contents"
kubectl delete all -n istio-system --all
kubectl delete ns istio-system

echo "deleting terminating namespaces"
./delete-terminating-namespaces.sh

set -e

cluster=$(cat cluster-name)
echo "scaling $cluster ng to 0"
yes | gcloud container clusters resize $cluster --node-pool default-pool --num-nodes 0 --zone $GKE_ZONE

echo "releasing cluster lock from $cluster"
kubectl annotate deployment lock lock-

rm cluster-name
