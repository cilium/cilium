#!/usr/bin/env bash

set -e

K8S_NODES=${K8S_NODES:-2}

echo "restarting portmap and nfs-kernel-server services to combat nfs server issues"
systemctl restart portmap.service || true
systemctl restart nfs-kernel-server.service || true

echo "destroying vms in case this is a retry"
for i in $(seq 1 $K8S_NODES); do
    vagrant destroy k8s${i}-${K8S_VERSION} --force
done

echo "boxes available on the node"
vagrant box list

echo "starting vms"
for i in $(seq 1 $K8S_NODES); do
    vagrant up k8s${i}-${K8S_VERSION} --provision
done

if [ -n "${KUBECONFIG}" ]; then
    echo "getting vagrant kubeconfig from provisioned vagrant cluster into ${KUBECONFIG}"
    ./get-vagrant-kubeconfig.sh > ${KUBECONFIG}
    KUBECTL="kubectl"
else
    echo "using vagrant ssh k8s1-${K8S_VERSION} for kubectl"
    # No kube config, run kubectl in k8s1 via ssh
    KUBECTL="vagrant ssh k8s1-${K8S_VERSION} -- kubectl"
fi

echo "checking whether kubeconfig works for vagrant cluster"
NEXT_WAIT_TIME=0
until ${KUBECTL} get nodes || [ $NEXT_WAIT_TIME -eq 12 ]; do
   ((NEXT_WAIT_TIME++))
   sleep 5
done

export HOME=${GOPATH}
${KUBECTL} get nodes

if [ -n "${CILIUM_REGISTRY}" ]; then
    echo "adding local docker registry to cluster"
    helm template registry-adder k8s/manifests/registry-adder --set IP="$(./print-node-ip.sh)" | ${KUBECTL} apply -f -
fi

echo "labeling nodes"
for i in $(seq 1 $K8S_NODES); do
    ${KUBECTL} label node k8s${i} cilium.io/ci-node=k8s${i} --overwrite
done
