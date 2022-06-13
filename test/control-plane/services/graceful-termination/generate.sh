#!/usr/bin/env bash
#
# Generate the golden test files for the graceful termination test
#
# This generates 3 event files:
# events1.yaml: Initial creation of the services and endpoints
# events2.yaml: Endpoint get set to terminating state
# events3.yaml: Endpoint is removed

set -eux

export KUBECONFIG=kubeconfig

function get_state() {
    kubectl get -n test services,endpointslices -o yaml
}

: Start a kind cluster with the EndpointSliceTerminatingCondition gate
kind create cluster --config kind-config.yaml --name graceful-term

: Wait for service account to be created
until kubectl get serviceaccount/default; do
    sleep 5
done

: Apply the graceful-termination.yaml and dump the initial state
kubectl create namespace test
kubectl apply -f graceful-termination.yaml
kubectl wait -n test --for=condition=ready --timeout=60s --all pods
get_state > events1.yaml

: Stop the server
kubectl -n test delete pod -l app=graceful-term-server &
PID_DELETE=$!

: Wait for endpoint to become terminating and then dump it
kubectl wait -n test --timeout=60s \
	-l kubernetes.io/service-name=graceful-term-svc \
	endpointslices \
	--for=jsonpath='{..endpoints..conditions.terminating}=true'
get_state > events2.yaml

: Finish deletion and dump the final state
wait $PID_DELETE
get_state > events3.yaml

: Tear down the cluster
kind delete clusters graceful-term
