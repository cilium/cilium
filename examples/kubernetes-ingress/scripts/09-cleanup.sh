#!/usr/bin/env bash
#
# Deletes all deployments created in kubernetes by the remaining scripts.
#######################################

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

log "Deleting all deployments deployed by this scripts in kubectl cluster..."

kubectl delete -f "${dir}/../deployments/guestbook/"

kubectl delete -f "${dir}/../deployments/guestbook/ingress"

kubectl delete -f "${dir}/../deployments/"

kubectl delete -f "${dir}/../network-policy/"

log "Deleting all deployments deployed by this scripts in kubectl cluster... DONE!"
