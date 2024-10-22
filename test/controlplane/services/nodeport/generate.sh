#!/usr/bin/env bash
#
# Generate the golden test files for the NodePort test.
# Reuses kind configs from the dual-stack test.
#

set -eux

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

. "${dir}/../../k8s_versions.sh"

export KUBECONFIG="${dir}/kubeconfig"

for version in ${versions[*]}; do
    mkdir -p "${dir}/v${version}"

    : Start a kind cluster
    kind create cluster --config "${dir}/../dualstack/manifests/kind-config-${version}.yaml" --name nodeport

    : Wait for service account to be created
    until kubectl get serviceaccount/default; do
        sleep 5
    done

    : Preloading images
    kind load --name nodeport docker-image "${cilium_container_repo}/${cilium_container_image}:${cilium_version}" || true
    kind load --name nodeport docker-image "${cilium_container_repo}/${cilium_operator_container_image}:${cilium_version}" || true || true

    : Install cilium
    cilium install --wait

    : Dump the initial state
    kubectl get nodes,ciliumnodes,services,endpoints,endpointslices -o yaml > "${dir}/v${version}/init.yaml"

    : Apply the manifest
    kubectl create namespace test
    kubectl apply -f "${dir}/manifests/nodeport.yaml"

    : Wait for all pods
    kubectl wait -n test --for=condition=ready --timeout=60s --all pods

    : Dump the services and endpoints
    kubectl get -n test services,endpoints,endpointslices,pods -o yaml > "${dir}/v${version}/state1.yaml"

    : Tear down the cluster
    kind delete clusters nodeport
    rm -f "${KUBECONFIG}"

done
