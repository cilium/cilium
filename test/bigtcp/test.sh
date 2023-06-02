#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# TODO: move to e2e tests running on Kind when they land

PS4='+[\t] '
set -eux

IMG_OWNER=${1:-cilium}
IMG_TAG=${2:-latest}
HELM_CHART_DIR=${3:-/vagrant/kubernetes/cilium}

# With Kind we create three nodes cluster:
#
# * "kind-control-plane"
# * "kind-worker" runs a netperf client.
# * "kind-worker2" runs a netperf server.
#

kind create cluster --config kind-config.yaml --image=kindest/node:v1.24.3

# Install Cilium with IPv6 BIG TCP enabled
helm install cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --set image.repository="quay.io/${IMG_OWNER}/cilium-ci" \
    --set image.tag="${IMG_TAG}" \
    --set image.useDigest=false \
    --set image.pullPolicy=IfNotPresent \
    --set devices='{eth0}' \
    --set ipv4.enabled=true \
    --set ipv6.enabled=true \
    --set routingMode='native' \
    --set enableIPv6Masquerade=false \
    --set bpf.masquerade=true \
    --set kubeProxyReplacement=strict \
    --set ipam.mode=kubernetes \
    --set nodePort.enabled=true \
    --set autoDirectNodeRoutes=true \
    --set hostLegacyRouting=false \
    --set ipv4NativeRoutingCIDR="10.0.0.0/8" \
    --set enableIPv6BIGTCP=true

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# check if BIG TCP is initialized
kubectl -n kube-system logs ds/cilium 2>&1 | grep "Setting up IPv6 BIG TCP"

# verify workers' gso_max_size
gsoSize=`docker exec kind-worker ip -d -j link show dev eth0 | jq -c '.[0].gso_max_size'`
if [ $gsoSize -le 65536 ]; then
	echo "Failed setting BIG TCP GSO max size ($gsoSize)";
	exit 1;
fi
gsoSize=`docker exec kind-worker ip -d -j link show dev eth0 | jq -c '.[0].gso_max_size'`
if [ $gsoSize -le 65536 ]; then
	echo "Failed setting BIG TCP GSO max size ($gsoSize)";
	exit 1;
fi

kubectl apply -f netperf.yaml
kubectl wait --timeout=1m --for=condition=ready pod -l app.kubernetes.io/name=netperf-server
kubectl wait --timeout=1m --for=condition=ready pod -l app.kubernetes.io/name=netperf-client

# verify pods' gso_max_size
gsoSize=`kubectl exec netperf-server -- ip -d -j link show dev eth0 | jq -c '.[0].gso_max_size'`
if [ $gsoSize -le 65536 ]; then
	echo "Failed setting netperf-server pod BIG TCP GSO max size ($gsoSize)";
	exit 1;
fi
gsoSize=`kubectl exec netperf-client -- ip -d -j link show dev eth0 | jq -c '.[0].gso_max_size'`
if [ $gsoSize -le 65536 ]; then
	echo "Failed setting netperf-client pod BIG TCP GSO max size ($gsoSize)";
	exit 1;
fi

# test connectivity
NETPERF_SERVER=`kubectl get pod netperf-server -o jsonpath='{.status.podIPs}' | jq -r -c '.[].ip | select(contains(":") == true)'`
kubectl exec netperf-client -- netperf  -t TCP_RR -H ${NETPERF_SERVER} -- -r80000:80000 -O MIN_LATENCY,P90_LATENCY,P99_LATENCY,THROUGHPUT

# cleanup
kind delete cluster

#####################

echo "YAY!"
