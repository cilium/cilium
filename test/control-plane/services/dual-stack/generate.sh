#!/usr/bin/env bash
#
# Generate the golden test files for the DualStack test
#

set -eux

export KUBECONFIG=kubeconfig

versions=(1.20 1.22 1.24)

manifests=(
	# Creates the echo deployment with two echo replicas.
	manifests/echo-dpl.yaml

	# Allows all to echo.
	manifests/echo-policy.yaml

	# Creates dual-stack service for echo.
	manifests/echo-svc-dualstack.yaml
)

for version in ${versions[*]}; do
    mkdir -p v${version}

    : Start a kind cluster
    kind create cluster --config manifests/kind-config-${version}.yaml --name dual-stack

    : Wait for service account to be created
    until kubectl get serviceaccount/default; do
        sleep 5
    done

    : Install cilium
    cilium install --wait --config enable-ipv6=true

    : Dump the initial state
    kubectl get nodes,ciliumnodes,services,endpoints,endpointslices -o yaml > v${version}/init.yaml

    : Apply the manifests
    for m in ${manifests[*]}; do
    	kubectl apply -f $m
    done

    : Wait for all pods
    kubectl wait --for=condition=ready --timeout=60s --all pods

    : Dump the services and endpoints
    kubectl get services,endpoints,endpointslices -o yaml > v${version}/state1.yaml

    : Tear down the cluster
    kind delete clusters dual-stack
    rm -f kubeconfig

done
