#!/usr/bin/env bash
#
# Generate the golden test files for the NodePort test.
# Reuses kind configs from the dual-stack test.
#

set -eux

export KUBECONFIG=kubeconfig

versions=(1.20 1.22 1.24)

for version in ${versions[*]}; do
    mkdir -p v${version}

    : Start a kind cluster
    kind create cluster --config ../dualstack/manifests/kind-config-${version}.yaml --name nodeport

    : Wait for service account to be created
    until kubectl get serviceaccount/default; do
        sleep 5
    done

    : Install cilium
    cilium install --wait

    : Dump the initial state
    kubectl get nodes,ciliumnodes,services,endpoints,endpointslices -o yaml > v${version}/init.yaml

    : Apply the manifest
    kubectl create namespace test
    kubectl apply -f manifests/nodeport.yaml

    : Wait for all pods
    kubectl wait -n test --for=condition=ready --timeout=60s --all pods

    : Dump the services and endpoints
    kubectl get -n test services,endpoints,endpointslices,pods -o yaml > v${version}/state1.yaml

    : Tear down the cluster
    kind delete clusters nodeport
    rm -f kubeconfig

done
