#!/usr/bin/env bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -e
set -o pipefail

# Sample usages
# ./contrib/scripts/kind.sh
# IPv6=1 ./contrib/scripts/kind.sh
# NO_BUILD=1 ./contrib/scripts/kind.sh
# NO_PROVISION=1 ./contrib/scripts/kind.sh

# Enable IPv6 mode. By default using IPv4
export 'IPv6'="${IPv6:0}"
# Set NO_BUILD=1 to avoid building docker images again
export 'NO_BUILD'="${NO_BUILD:0}"
# Set NO_PROVISION=1 to use existing kind cluster
export 'NO_PROVISION'="${NO_PROVISION:0}"

function help() {
  printf "Run with default values:\n\t./contrib/scripts/kind.sh\n\n"
  printf "Using existing docker images:\n\t./contrib/scripts/kind.sh\n\n"
  printf "Using existing cluster:\n\tNO_PROVISION=1 ./contrib/scripts/kind.sh\n\n"
  exit 1
}

# Build cilium and cilium operator docker images
if [[ "${NO_BUILD}" -ne "1" ]]; then
  make -j docker-cilium-image docker-operator-generic-image
fi

# Provision kind cluster if required
if [[ "${NO_PROVISION}" -ne "1" ]]; then
  kind delete cluster
  # clean up previous kind network
  docker system prune -f

  if [[ "${IPv6}" -ne "1" ]]; then
    kind_config_file=.github/kind-config.yaml
  else
    kind_config_file=.github/kind-config-ipv6.yaml
  fi

  kind create cluster --config="$kind_config_file"
fi

# Load images into kind cluster
kind load docker-image cilium/cilium:latest
kind load docker-image cilium/operator-generic:latest

# Install cilium with helm, similar to what we have in smoketest
if [[ "${IPv6}" -ne "1" ]]; then
  helm upgrade -i cilium ./install/kubernetes/cilium \
    --wait \
    --namespace kube-system \
    --set nodeinit.enabled=true \
    --set kubeProxyReplacement=partial \
    --set hostServices.enabled=false \
    --set externalIPs.enabled=true \
    --set nodePort.enabled=true \
    --set hostPort.enabled=true \
    --set bpf.masquerade=false \
    --set ipam.mode=kubernetes \
    --set image.tag=latest \
    --set image.pullPolicy=Never \
    --set operator.image.tag=latest \
    --set operator.image.pullPolicy=Never \
    --set prometheus.enabled=true \
    --set operator.prometheus.enabled=true \
    --set hubble.enabled=true \
    --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"
else
  helm upgrade -i cilium ./install/kubernetes/cilium \
    --wait \
    --namespace kube-system \
    --set nodeinit.enabled=true \
    --set kubeProxyReplacement=strict \
    --set ipam.mode=kubernetes \
    --set image.tag=latest \
    --set image.pullPolicy=Never \
    --set operator.image.tag=latest \
    --set operator.image.pullPolicy=Never \
    --set ipv6.enabled=true \
    --set ipv4.enabled=false \
    --set tunnel=disabled \
    --set autoDirectNodeRoutes=true \
    --set prometheus.enabled=true \
    --set operator.prometheus.enabled=true \
    --set hubble.enabled=true \
    --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"
fi

kubectl wait -n kube-system --for=condition=Ready --all pod --timeout=60s
kubectl wait --for condition=Established crd/ciliumnetworkpolicies.cilium.io --timeout=60s

# Run connectivity check
if [[ "${IPv6}" -ne "1" ]]; then
  kubectl apply -f examples/kubernetes/connectivity-check/connectivity-check.yaml
else
  kubectl apply -f examples/kubernetes/connectivity-check/connectivity-check-internal.yaml
fi
