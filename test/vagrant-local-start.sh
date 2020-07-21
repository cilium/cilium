#!/bin/bash

set -e

export K8S_VERSION=${K8S_VERSION:-1.19}
export K8S_NODES=${K8S_NODES:-2}
export LOCAL_BOX=k8s-box
export LOCAL_BOXFILE=./.vagrant/${LOCAL_BOX}-package.box

echo "destroying vms"
i=1
while vagrant destroy k8s${i}-${K8S_VERSION} --force 2>/dev/null
do
  (( i++ ))
done

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
for i in $( seq 1 ${K8S_NODES} )
do
  echo "Starting k8s${i}-${K8S_VERSION}"
  vagrant up k8s${i}-${K8S_VERSION} --provision
done

echo "labeling nodes"
for i in $( seq 1 ${K8S_NODES} )
do
  echo "Labeling k8s${i}-${K8S_VERSION}"
  vagrant ssh k8s1-${K8S_VERSION} -- kubectl label node k8s${i} cilium.io/ci-node=k8s${i} --overwrite
done
