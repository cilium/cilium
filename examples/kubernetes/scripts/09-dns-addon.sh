#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

kubectl create -f "${dir}/../deployments/kubedns-svc.yaml"

kubectl create -f "${dir}/../deployments/kubedns-rc.yaml"

kubectl --namespace=kube-system get svc
kubectl --namespace=kube-system get pods
