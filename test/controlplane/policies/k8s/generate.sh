#!/usr/bin/env bash
#
# Generate the golden test files for the NodePort test.
# Reuses kind configs from the dual-stack test.
#

set -eux

export KUBECONFIG=kubeconfig

resources="services,endpoints,endpointslices,pods,networkpolicies,ciliumnetworkpolicies"
versions=(1.20 1.22 1.24)

for version in ${versions[*]}; do
    mkdir -p v${version}

    : Start a kind cluster
    kind create cluster --config manifests/kind-config-${version}.yaml --name policy

    : Wait for service account to be created
    until kubectl get serviceaccount/default; do
        sleep 5
    done

    : Install cilium
    cilium install --wait

    : Dump the initial state
    kubectl get nodes,ciliumnodes,$resources -o yaml > v${version}/init.yaml

    : Apply the manifest and dump the final state
    kubectl create namespace policy1
    kubectl apply -n policy1 -f manifests/knp-default-allow-egress.yaml
    kubectl get -n policy1 $resources -o yaml > v${version}/state1.yaml

    kubectl create namespace policy2
    kubectl apply -n policy2 -f manifests/knp-default-allow-ingress.yaml
    kubectl get -n policy2 $resources -o yaml > v${version}/state2.yaml

    kubectl create namespace policy3
    kubectl apply -n policy3 -f manifests/knp-default-deny-egress.yaml
    kubectl get -n policy3 $resources -o yaml > v${version}/state3.yaml

    kubectl create namespace policy4
    kubectl apply -n policy4 -f manifests/knp-default-deny-ingress.yaml
    kubectl get -n policy4 $resources -o yaml > v${version}/state4.yaml

    kubectl create namespace policy5
    kubectl apply -n policy5 -f manifests/knp-default-deny-ingress-egress.yaml
    kubectl get -n policy5 $resources -o yaml > v${version}/state5.yaml

    : Tear down the cluster
    kind delete clusters policy
    rm -f kubeconfig

done
