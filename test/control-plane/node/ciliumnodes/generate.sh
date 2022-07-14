#!/usr/bin/env bash
#
# Generate the golden test files for the Node test
#

set -eux

export KUBECONFIG=kubeconfig

versions=(1.20 1.22 1.24)

for version in ${versions[*]}; do
    mkdir -p v${version}

    : Start a kind cluster
    kind create cluster --config manifests/kind-config-${version}.yaml --name cilium-nodes

    : Install cilium
    cilium install --wait

    : Dump the initial state
    kubectl get nodes,ciliumnodes -o yaml > v${version}/init.yaml

    : Apply the label to worker node
    kubectl label nodes cilium-nodes-worker test-label=test-value

    : Wait for all nodes to be ready
    kubectl wait --for=condition=ready --timeout=60s --all nodes

    : Dump the nodes
    kubectl get nodes -o yaml > v${version}/state1.yaml

    : Remove the label
    kubectl label nodes cilium-nodes-worker test-label-

    : Wait for all nodes to be ready
    kubectl wait --for=condition=ready --timeout=60s --all nodes

    : Dump the nodes
    kubectl get nodes -o yaml > v${version}/state2.yaml

    : Tear down the cluster
    kind delete clusters cilium-nodes
    rm -f kubeconfig

done
