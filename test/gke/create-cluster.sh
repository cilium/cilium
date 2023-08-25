#!/usr/bin/env bash

if [ "$#" != 1 ]; then
    >&2 printf "Illegal number of parameters\n"
    >&2 printf "Usage: ./select-cluster.sh owner_pipeline_name\n"
    exit 1
fi

# replace . with - in job name due to GKE only accepting dashes and alphanumeric
# characters in cluster names
owner_pipeline_name="${1/./-}"

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

project="cilium-ci"
zone="us-west1-a"
labels="usage=cilium-jenkins,owner=${owner_pipeline_name}"

set -e

echo "creating new cluster"
gcloud container clusters create "${owner_pipeline_name}" \
  --project "${project}" \
	--zone "${zone}" \
	--labels "${labels}" \
	--image-type COS_CONTAINERD \
	--num-nodes 2 \
	--machine-type n1-standard-4 \
	--disk-type pd-standard \
	--disk-size 100GB \
	--enable-service-externalips \
	--preemptible
# --enable-service-externalips is required for our tests, as the
# `DenyServiceExternalIPs` admission controller is now enabled by default on GKE
# version 1.21 and above, cf. https://cloud.google.com/kubernetes-engine/docs/release-notes#December_20_2021

cluster_uri=$(gcloud container clusters describe --project "${project}" --zone "${zone}" --format='value(uri())' "${owner_pipeline_name}")

export KUBECONFIG="${script_dir}/gke-kubeconfig"
echo "getting kubeconfig for ${cluster_uri} (will store in ${KUBECONFIG})"
gcloud container clusters get-credentials --project "${project}" --zone "${zone}" "${cluster_uri}"

echo "${cluster_uri}" > "${script_dir}/cluster-uri"
gcloud container clusters describe --project "${project}" --zone "${zone}" --format='value(name)' "${cluster_uri}" > "${script_dir}/cluster-name"
gcloud container clusters describe --project "${project}" --zone "${zone}" --format='value(currentMasterVersion)' "${cluster_uri}" \
    | sed -E 's/([0-9]+\.[0-9]+)\..*/\1/' | tr -d '\n' > "${script_dir}/cluster-version"
gcloud container clusters describe --project "${project}" --zone "${zone}" --format='value(clusterIpv4Cidr)' "${cluster_uri}" > "${script_dir}/cluster-cidr"

echo "labeling nodes"
index=1
for node in $(kubectl get nodes --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}');
do
    kubectl label node "$node" cilium.io/ci-node=k8s"$index" --overwrite
    index=$((index+1))
done
