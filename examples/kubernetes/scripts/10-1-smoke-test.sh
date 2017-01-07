#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

kubectl create -f "${dir}/../deployments/guestbook/1-redis-master-controller.json"
kubectl create -f "${dir}/../deployments/guestbook/2-redis-master-service.json"
kubectl create -f "${dir}/../deployments/guestbook/3-redis-slave-controller.json"
kubectl create -f "${dir}/../deployments/guestbook/4-redis-slave-service.json"
kubectl create -f "${dir}/../deployments/guestbook/5-guestbook-controller.json"
kubectl create -f "${dir}/../deployments/guestbook/6-guestbook-service.json"

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

worker=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' | grep guestbook | cut -d' ' -f2)

podIP=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.status.podIP}{"\n"}{end}' | grep guestbook | cut -d' ' -f2)

echo "sudo apt-get install socat -y && sudo socat TCP-LISTEN:3000,fork TCP:${podIP}:3000" > "./10-2-run-inside-${worker}.sh"

chmod +x "./10-2-run-inside-${worker}.sh"

echo "Please run ./10-2-run-inside-${worker}.sh inside ${worker}"
