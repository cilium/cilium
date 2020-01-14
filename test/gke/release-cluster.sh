#!/bin/bash

set -e

zone=europe-west4-a
export KUBECONFIG=gke-kubeconfig

cluster=$(cat cluster-name)
echo "scaling $cluster ng to 0"
yes | gcloud container clusters resize $cluster --node-pool default-pool --num-nodes 0 --zone $zone

echo "releasing cluster lock from $cluster"
kubectl annotate deployment lock lock-

rm cluster-name
