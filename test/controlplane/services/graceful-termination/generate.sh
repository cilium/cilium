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

export KUBECONFIG=kubeconfig

function get_state() {
    kubectl get -n test services,endpointslices -o yaml
}

: Start a kind cluster with the EndpointSliceTerminatingCondition gate
kind create cluster --config manifests/kind-config.yaml --name graceful-term

: Wait for service account to be created
until kubectl get serviceaccount/default; do
    sleep 5
done

: Install cilium
cilium install --wait

: Dump the initial state
kubectl get nodes,ciliumnodes,services,endpointslices -o yaml > init.yaml

: Apply the graceful-termination.yaml and dump the initial state
kubectl create namespace test
kubectl apply -f manifests/graceful-termination.yaml
kubectl wait -n test --for=condition=ready --timeout=60s --all pods
get_state > state1.yaml

: Stop the server
kubectl -n test delete pod -l app=graceful-term-server &
PID_DELETE=$!

: Wait for endpoint to become terminating and then dump it
kubectl wait -n test --timeout=60s \
	-l kubernetes.io/service-name=graceful-term-svc \
	endpointslices \
	--for=jsonpath='{..endpoints..conditions.terminating}=true'
get_state > state2.yaml

: Finish deletion and dump the final state
wait $PID_DELETE
get_state > state3.yaml

: Tear down the cluster
kind delete clusters graceful-term
rm -f kubeconfig
