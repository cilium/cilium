#!/usr/bin/env bash
#
# Configures and creates kubernetes ingress controller, it will use default
# values from ./helpers.bash
#######################################

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

log "Installing ingress into kubectl cluster..."

set -e

ingress="${dir}/../deployments/guestbook/ingress"

kubectl create -f "${ingress}" || true

kubectl --namespace=kube-system get svc
kubectl --namespace=kube-system get pods

log "Installing ingress into kubectl cluster... DONE!"
