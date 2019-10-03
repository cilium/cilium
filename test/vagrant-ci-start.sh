#!/bin/bash

set -e

echo "destroying vms in case this is a retry"
vagrant destroy k8s1-${K8S_VERSION} k8s2-${K8S_VERSION} --force

echo "starting vms"
vagrant up k8s1-${K8S_VERSION} k8s2-${K8S_VERSION} --provision

echo "getting vagrant kubeconfig from provisioned vagrant cluster"
./get-vagrant-kubeconfig.sh > vagrant-kubeconfig

echo "checking whether kubeconfig works for vagrant cluster"
kubectl get nodes

echo "adding local docker registry to cluster"
helm template k8sT/manifests/registry-adder --set IP="$(./print-node-ip.sh)" > registry-adder.yaml
kubectl apply -f registry-adder.yaml
