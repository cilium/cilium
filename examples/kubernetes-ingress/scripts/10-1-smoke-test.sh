#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

kubectl create -f "${dir}/../deployments/guestbook/"

kubectl get pods -o wide

while [[ "$(kubectl get pods | grep guestbook | grep Running -c)" -ne "1" ]] ; do
    echo "Waiting for guestbook pod to be Running..."
    sleep 2s
done

while [[ "$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.status.podIP}{"\n"}{end}' 2>&1 | grep guestbook -c )"  -ne "1" ]] ; do
    echo "Waiting for guestbook pod to have a pod IP assigned..."
    kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.status.podIP}{"\n"}{end}'
    sleep 2s
done

kubectl create -f "${dir}/../deployments/guestbook/ingress/"
