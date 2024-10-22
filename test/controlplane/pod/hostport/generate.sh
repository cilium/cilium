#!/usr/bin/env bash
#
# Generate the golden test files for the HostPort test.
#

set -eux

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

. "${dir}/../../k8s_versions.sh"

export KUBECONFIG="${dir}/kubeconfig"

: Start a kind cluster
kind create cluster --config "${dir}/manifests/kind-config-1.26.yaml" --name hostport

: Wait for service account to be created
until kubectl get serviceaccount/default; do
    sleep 5
done

: Preloading images
kind load --name hostport docker-image "${cilium_container_repo}/${cilium_container_image}:${cilium_version}" || true
kind load --name hostport docker-image "${cilium_container_repo}/${cilium_operator_container_image}:${cilium_version}" || true || true

: Install cilium
cilium install --wait

: Dump the initial state
kubectl get nodes,pods -o yaml > "${dir}/init.yaml"

: Apply manifest for hostport-1 pod
kubectl create namespace test
kubectl apply -f "${dir}/manifests/hostport-1.yaml"

: Wait for all pods
kubectl wait -n test --for=condition=ready --timeout=60s pod hostport-1

: Dump the pods
kubectl get -n test pods -o yaml > "${dir}/state1.yaml"

: Put hostport-1 pod in "completed" by terminating nginx container.
kubectl -n test exec -it hostport-1 -c nginx -- /bin/sh -c "kill 1"

: Apply manifest for hostport-2 pod and wait for all pods
kubectl apply -f "${dir}/manifests/hostport-2.yaml"
kubectl wait -n test --for=condition=ready --timeout=60s pod hostport-2

: Dump the pods
kubectl get -n test pods -o yaml > "${dir}/state2.yaml"

: Deleted the completed hostport-1 pod.
kubectl -n test delete pod hostport-1

: Dump the final state
kubectl get -n test pods -o yaml > "${dir}/state3.yaml"

: Tear down the cluster
kind delete clusters hostport
rm -f "${KUBECONFIG}"
