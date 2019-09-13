#!/bin/bash

set -e

K8S_VERSION_NO_DOTS=$(echo $K8S_VERSION | sed "s/\.//g")

config=$(vagrant ssh k8s1-${K8S_VERSION} -- sudo cat /etc/kubernetes/admin.conf)
port=$(cat .vagrant/machines/k8s1-${K8S_VERSION}/virtualbox/id | xargs vboxmanage showvminfo --machinereadable | grep 'Forwarding.*6443' | awk -F ',' '{print $4}')
echo "$config" | sed "s/6443/$port/g"
