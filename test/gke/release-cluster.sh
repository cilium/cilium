#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

project="cilium-ci"
zone="us-west1-a"

if [ ! -f "${script_dir}/cluster-uri"  ]; then
    echo "Cluster uri file not found, exiting"
    exit 1
fi

cluster_uri="$(cat "${script_dir}/cluster-uri")"
cluster_name=${cluster_uri##*/}

export KUBECONFIG="${script_dir}/gke-kubeconfig"

while [ "$(gcloud container operations list --project "${project}" --filter="status=RUNNING AND targetLink=${cluster_uri}" --format="value(name)")" ]
do
    echo "cluster has an ongoing operation, waiting for all operations to finish"
    sleep 15
done

echo "deleting cluster ${cluster_uri}"
gcloud container clusters delete --project "${project}" --zone "${zone}" "${cluster_uri}" --quiet --async

rm -f "${script_dir}/cluster-uri" "${script_dir}/cluster-name" "${script_dir}/cluster-version" "${script_dir}/registry-adder.yaml"
