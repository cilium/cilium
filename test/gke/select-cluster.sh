#!/bin/bash

set -e

locked=1

export KUBECONFIG=gke-kubeconfig

while [ $locked -ne 0 ]; do
    rm gke-kubeconfig || true
    echo "selecting random cluster"
    cluster=$(gcloud container clusters list --zone $GKE_ZONE | grep cilium-ci | sort -R | head -n 1 | awk '{print $1}')

    echo "getting kubeconfig for $cluster"
    gcloud container clusters get-credentials --zone $GKE_ZONE $cluster

    echo "aquiring cluster lock"
    set +e
    kubectl create -f lock.yaml

    kubectl annotate deployment lock lock=1
    locked=$?
    echo $locked
    set -e
done

echo "lock acquired on cluster $cluster"
# cluster-name is used in get-cluster-version.sh, which runs after this in CI.
echo $cluster > cluster-name

echo "creating cilium ns"
kubectl create ns cilium || true

echo "deleting terminating namespaces"
./delete-terminating-namespaces.sh

echo "scaling $cluster to 2"
yes | gcloud container clusters resize $cluster --node-pool default-pool --num-nodes 2 --zone $GKE_ZONE

echo "labeling nodes"
index=1
for node in $(kubectl get nodes --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}');
do
    kubectl label node $node cilium.io/ci-node=k8s$index --overwrite
    index=$((index+1))
done

echo "adding node registry as trusted"
helm template registry-adder ../k8sT/manifests/registry-adder-gke --set IP="$(../print-node-ip.sh)" > registry-adder.yaml
kubectl apply -f registry-adder.yaml
