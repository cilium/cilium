#!/usr/bin/env bash

set -e

export K8S_VERSION=${K8S_VERSION:-1.19}
export LOCAL_BOX=k8s-box
export LOCAL_BOXFILE=./.vagrant/${LOCAL_BOX}-package.box

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

export SERVER_BOX=$LOCAL_BOX
export SERVER_VERSION=0
unset PRELOAD_VM
