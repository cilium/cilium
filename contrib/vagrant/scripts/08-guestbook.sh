#!/usr/bin/env bash
#
# Creates guestbook example and waits for it to be ready to use.
#######################################

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

log "Installing guestbook into kubectl cluster..."

set -e

kubectl create -f "${dir}/../network-policy/" || true

kubectl create -f "${dir}/../deployments/guestbook/"

kubectl get pods -o wide

while [[ "$(kubectl get pods | grep guestbook | grep Running -c)" -ne "1" ]] ; do
    log "Waiting for guestbook pod to be Running..."
    sleep 2s
done

while [[ "$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.status.podIP}{"\n"}{end}' 2>&1 | grep guestbook -c )"  -ne "1" ]] ; do
    log "Waiting for guestbook pod to have a pod IP assigned..."
    kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.status.podIP}{"\n"}{end}'
    sleep 2s
done

log "Installing guestbook into kubectl cluster... DONE!"
