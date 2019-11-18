#!/bin/bash

set -e

export K8S_VERSION=${K8S_VERSION:-1.16}
export LOCAL_BOX=k8s-box
export LOCAL_BOXFILE=/tmp/${LOCAL_BOX}-package.box

echo "destroying vms"
vagrant destroy k8s1-${K8S_VERSION} k8s2-${K8S_VERSION} --force || true

if [[ ! -f ${LOCAL_BOXFILE} ]]; then
  echo "Updating vm image"
  unset SERVER_BOX
  unset SERVER_VERSION
  export PRELOAD_VM=true
  vagrant up k8s1-${K8S_VERSION} --provision
  vagrant package k8s1-${K8S_VERSION} --output ${LOCAL_BOXFILE}
  vagrant box add --name ${LOCAL_BOX} ${LOCAL_BOXFILE} --force
  vagrant destroy k8s1-${K8S_VERSION} --force
fi

echo "starting vms"
export SERVER_BOX=$LOCAL_BOX
export SERVER_VERSION=0
unset PRELOAD_VM
vagrant up k8s1-${K8S_VERSION} k8s2-${K8S_VERSION} --provision

echo "labeling nodes"
vagrant ssh k8s1-${K8S_VERSION} -- kubectl label node k8s1 cilium.io/ci-node=k8s1 --overwrite
vagrant ssh k8s1-${K8S_VERSION} -- kubectl label node k8s2 cilium.io/ci-node=k8s2 --overwrite
