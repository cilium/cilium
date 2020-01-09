#!/bin/bash

set -e

K8S_NODES=${K8S_NODES:-2}

echo "destroying vms in case this is a retry"
for i in $(seq 1 $K8S_NODES); do
    vagrant destroy k8s${i}-${K8S_VERSION} --force
done

echo "starting vms"
for i in $(seq 1 $K8S_NODES); do
    vagrant up k8s${i}-${K8S_VERSION} --provision
done

echo "getting vagrant kubeconfig from provisioned vagrant cluster"
./get-vagrant-kubeconfig.sh > vagrant-kubeconfig

echo "checking whether kubeconfig works for vagrant cluster"
kubectl get nodes

echo "adding local docker registry to cluster"
helm template k8sT/manifests/registry-adder --set IP="$(./print-node-ip.sh)" > registry-adder.yaml
kubectl apply -f registry-adder.yaml

echo "labeling nodes"
for i in $(seq 1 $K8S_NODES); do
    kubectl label node k8s${i} cilium.io/ci-node=k8s${i}
done
