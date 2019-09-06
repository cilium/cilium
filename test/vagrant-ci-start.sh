#!/bin/bash

set -e

vagrant destroy k8s1-${K8S_VERSION} k8s2-${K8S_VERSION} --force
vagrant up k8s1-${K8S_VERSION} k8s2-${K8S_VERSION} --provision

./get-vagrant-kubeconfig.sh > vagrant-kubeconfig

vagrant ssh k8s1-${K8S_VERSION} -- sudo cat /etc/kubernetes/admin.conf

kubectl get nodes
