#!/bin/bash

echo "dry running ginkgo"
ginkgo --dryRun $@ > /dev/null

if [ $? -ne 0 ]
then
	echo "failed to dry run ginkgo"
	ginkgo --dryRun $@
	exit 1
fi

set -e

vagrant up k8s1-${K8S_VERSION} k8s2-${K8S_VERSION}


echo "getting vagrant kubeconfig from provisioned vagrant cluster"
./get-vagrant-kubeconfig.sh > vagrant-kubeconfig

export KUBECONFIG=vagrant-kubeconfig

echo "checking whether kubeconfig works for vagrant cluster"
kubectl get nodes

echo "labeling nodes"
kubectl label --overwrite node k8s1 cilium.io/ci-node=k8s1
kubectl label --overwrite node k8s2 cilium.io/ci-node=k8s2

kubeconfig="-- -cilium.kubeconfig=$(pwd)/vagrant-kubeconfig"
compile=1

#if there are additional cilium ginkgo flags provided as arguments  we drop the double dash from ginkgo call
for arg in "$@"
do
	if [ "$arg" == "--" ]
	then
		kubeconfig="-cilium.kubeconfig=$(pwd)/vagrant-kubeconfig"
	fi
	if [ "$arg" == "-cilium.provision=false" ]
	then
		compile=0
	fi
done

# compiling Cilium is skipped if cilium.provision flag is set to false
if [ $compile -eq 1 ]
then
	vagrant ssh k8s1-${K8S_VERSION} --command /tmp/provision/compile.sh
fi

ginkgo $@ $kubeconfig
