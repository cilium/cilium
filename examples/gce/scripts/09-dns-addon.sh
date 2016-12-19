#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/kubedns-svc.yaml

kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/kubedns-rc.yaml


kubectl --namespace=kube-system get svc
kubectl --namespace=kube-system get pods
