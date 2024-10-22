#!/usr/bin/env bash
#
# Generate the golden test files for the DualStack test
#

set -eux

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

. "${dir}/../../k8s_versions.sh"

export KUBECONFIG="${dir}/kubeconfig"

manifests=(
	# Creates the echo deployment with two echo replicas.
	manifests/echo-dpl.yaml

	# Allows all to echo.
	manifests/echo-policy.yaml

	# Creates dual-stack service for echo.
	manifests/echo-svc-dualstack.yaml
)

for version in ${versions[*]}; do
    mkdir -p "${dir}/v${version}"

    : Start a kind cluster
    kind create cluster --config "${dir}/manifests/kind-config-${version}.yaml" --name dual-stack

    : Preloading images
    kind load --name dual-stack docker-image "${cilium_container_repo}/${cilium_container_image}:${cilium_version}" || true
    kind load --name dual-stack docker-image "${cilium_container_repo}/${cilium_operator_container_image}:${cilium_version}" || true || true

    : Wait for service account to be created
    until kubectl get serviceaccount/default; do
        sleep 5
    done

    : Install cilium
    cilium install --wait --config enable-ipv6=true

    : Dump the initial state
    kubectl get nodes,ciliumnodes,services,endpoints,endpointslices -o yaml > "${dir}/v${version}/init.yaml"

    : Apply the manifests
    for m in ${manifests[*]}; do
    	kubectl apply -f "${dir}/$m"
    done

    : Wait for all pods
    kubectl wait --for=condition=ready --timeout=60s --all pods

    : Dump the services and endpoints
    kubectl get services,endpoints,endpointslices -o yaml > "${dir}/v${version}/state1.yaml"

    : Tear down the cluster
    kind delete clusters dual-stack
    rm -f "${KUBECONFIG}"

done
