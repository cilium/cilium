#!/bin/bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

project="cilium-ci"
region="us-west1"

cluster_uri="$(cat "${script_dir}/cluster-uri")"
cluster_name=${cluster_uri##*/}

gcloud container clusters delete --quiet --zone ${region} "${cluster_uri}"

export KUBECONFIG="${script_dir}/resize-kubeconfig"
gcloud container clusters get-credentials --project "${project}" --region "europe-west4" management-cluster-0
kubectl delete containerclusters.container.cnrm.cloud.google.com -n test-clusters "${cluster_name}"

rm -f "${script_dir}/cluster-uri" "${script_dir}/cluster-name" "${script_dir}/cluster-version" "${script_dir}/registry-adder.yaml"
