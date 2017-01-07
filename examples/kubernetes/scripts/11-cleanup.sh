#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

kubectl delete -f "${dir}/../deployments/guestbook/"

kubectl delete -f "${dir}/../deployments/kubedns-rc.yaml" -f "${dir}/../deployments/kubedns-svc.yaml"

kubectl delete -f "${dir}/../network-policy/"
