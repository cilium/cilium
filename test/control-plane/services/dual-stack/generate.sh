#!/usr/bin/env bash
#
# Generate the golden test files for the DualStack test
#

set -eux

export KUBECONFIG=kubeconfig

manifests=(
	manifests/demo.yaml
	manifests/demo_ds.yaml
	manifests/echo-svc.yaml
	manifests/echo-policy.yaml
	manifests/demo_v6.yaml
	manifests/demo_ds_v6.yaml
	manifests/echo-svc_v6.yaml
	manifests/echo_svc_dualstack.yaml
)

: Start a kind cluster
kind create cluster --config kind-config.yaml --name dual-stack

: Wait for service account to be created
until kubectl get serviceaccount/default; do
    sleep 5
done

: Install cilium
cilium install --wait --config enable-ipv6=true

: Apply the manifests
for m in ${manifests[*]}; do
	kubectl apply -f $m
done

: Wait for all pods
kubectl wait --for=condition=ready --timeout=60s --all pods

: Dump the services and endpoints
kubectl get services,endpointslices -o yaml > events1.yaml

: Tear down the cluster
# kind delete clusters dual-stack
