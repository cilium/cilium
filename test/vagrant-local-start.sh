#!/bin/bash

set -e

export K8S_VERSION=${K8S_VERSION:-1.21}
export K8S_NODES=${K8S_NODES:-2}

echo "destroying vms"
i=1
while vagrant destroy k8s${i}-${K8S_VERSION} --force 2>/dev/null
do
  (( i++ ))
done

if [ "$PRELOAD_VM" != "false" ]; then
    ./vagrant-local-create-box.sh
else
    # Use defaults (see ../vagrant_box_defaults.rb)
    unset SERVER_BOX
    unset SERVER_VERSION
fi

echo "starting vms"
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
