#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

if [ -n "${INSTALL}" ]; then
    wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kubectl
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin
fi

KUBERNETES_PUBLIC_ADDRESS="192.168.34.11"

kubectl config set-cluster cilium-k8s-local \
  --server=http://${KUBERNETES_PUBLIC_ADDRESS}:8080

kubectl config set-credentials admin --token chAng3m3

kubectl config set-context default-context \
  --cluster=cilium-k8s-local \
  --user=admin

kubectl config use-context default-context

kubectl get componentstatuses

kubectl get nodes
