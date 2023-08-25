#!/usr/bin/env bash
#
# Generate the golden test files for the graceful termination test
#
# This generates the following files:
# init.yaml: The initial state of the cluster
# state1.yaml: Initial creation of the services and endpoints
# state2.yaml: Endpoint is set to terminating state
# state3.yaml: Endpoint has been removed

set -eux

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

. "${dir}/../../k8s_versions.sh"

export KUBECONFIG="${dir}/kubeconfig"

function get_state() {
    kubectl get -n test services,endpointslices -o yaml
}

: Start a kind cluster with the EndpointSliceTerminatingCondition gate
kind create cluster --config "${dir}/manifests/kind-config-1.26.yaml" --name graceful-term

: Wait for service account to be created
until kubectl get serviceaccount/default; do
    sleep 5
done

: Preloading images
kind load --name graceful-term docker-image "${cilium_container_repo}/${cilium_container_image}:${cilium_version}" || true
kind load --name graceful-term docker-image "${cilium_container_repo}/${cilium_operator_container_image}:${cilium_version}" || true || true

: Install cilium
cilium install --wait

: Dump the initial state
kubectl get nodes,ciliumnodes,services,endpointslices -o yaml > "${dir}/init.yaml"

: Apply the graceful-termination.yaml and dump the initial state
kubectl create namespace test
kubectl apply -f "${dir}/manifests/graceful-termination.yaml"
kubectl wait -n test --for=condition=ready --timeout=60s --all pods
get_state > "${dir}/state1.yaml"

: Stop the server
kubectl -n test delete pod -l app=graceful-term-server &
PID_DELETE=$!

: Wait for endpoint to become terminating and then dump it
kubectl wait -n test --timeout=60s \
	-l kubernetes.io/service-name=graceful-term-svc \
	endpointslices \
	--for=jsonpath='{..endpoints..conditions.terminating}=true'
get_state > "${dir}/state2.yaml"

: Finish deletion and dump the final state
wait $PID_DELETE
get_state > "${dir}/state3.yaml"

: Tear down the cluster
kind delete clusters graceful-term
rm -f "${KUBECONFIG}"
