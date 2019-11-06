#!/bin/bash

set -e

echo "starting vms"

if [ "$2" == "provision" ]
then
	vagrant up k8s1-${K8S_VERSION} k8s2-${K8S_VERSION} --provision
else
	vagrant up k8s1-${K8S_VERSION} k8s2-${K8S_VERSION}
fi

echo "compiling Cilium"
vagrant ssh k8s1-${K8S_VERSION} --command /tmp/provision/compile.sh

echo "getting vagrant kubeconfig from provisioned vagrant cluster"
./get-vagrant-kubeconfig.sh > vagrant-kubeconfig

export KUBECONFIG=vagrant-kubeconfig

echo "checking whether kubeconfig works for vagrant cluster"
kubectl get nodes

echo "labeling nodes"
kubectl label --overwrite node k8s1 cilium.io/ci-node=k8s1
kubectl label --overwrite node k8s2 cilium.io/ci-node=k8s2

export CILIUM_IMAGE=k8s1:5000/cilium/cilium:latest

export CILIUM_OPERATOR_IMAGE=k8s1:5000/cilium/operator:latest

ginkgo --focus="$1" -v -- -cilium.provision=false -cilium.timeout=110m -cilium.kubeconfig=$(pwd)/vagrant-kubeconfig -cilium.passCLIEnvironment=true
