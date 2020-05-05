#!/bin/bash

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

project="cilium-ci"
# this is only needs to be set as some of gcloud commands requires it,
# but as this script uses resource URIs clusters in all locations are
# going to be discovered and used
region="us-west2"

set -e

locked=1

export KUBECONFIG="${script_dir}/gke-kubeconfig"

while [ $locked -ne 0 ]; do
    rm -f "${KUBECONFIG}"
    echo "selecting random cluster"
    cluster_uri="$(gcloud container clusters list --project "${project}" --filter="name ~ ^cilium-ci-" --uri | sort -R | head -n 1)"

    echo "getting kubeconfig for ${cluster_uri} (will store in ${KUBECONFIG})"
    gcloud container clusters get-credentials --project "${project}" --region "${region}" "${cluster_uri}"

    echo "aquiring cluster lock"
    set +e
    kubectl create -f "${script_dir}/lock.yaml"

    kubectl annotate deployment lock lock=1
    locked=$?
    echo $locked
    set -e
done

echo "lock acquired on cluster ${cluster_uri}"
echo "${cluster_uri}" > "${script_dir}/cluster-uri"
gcloud container clusters describe --project "${project}" --region "${region}" --format='value(name)' "${cluster_uri}" > "${script_dir}/cluster-name"
gcloud container clusters describe --project "${project}" --region "${region}" --format='value(currentMasterVersion)' "${cluster_uri}" \
  | sed -E 's/([0-9]+\.[0-9]+)\..*/\1/' | tr -d '\n' > "${script_dir}/cluster-version"

echo "creating cilium ns"
kubectl create ns cilium || true

echo "deleting terminating namespaces"
${script_dir}/delete-terminating-namespaces.sh

echo "scaling $cluster to 2"
node_pools=($(gcloud container node-pools list --project "${project}" --region "${region}" --cluster "${cluster_uri}" --uri))
if [ "${#node_pools[@]}" -ne 1 ] ; then
  echo "expected 1 node pool, found ${#node_pools[@]}"
  exit 1
fi

gcloud container clusters resize --project "${project}" --region "${region}" --node-pool "${node_pools[1]}" --num-nodes 2 --quiet "${cluster_uri}"

echo "labeling nodes"
index=1
for node in $(kubectl get nodes --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}');
do
    kubectl label node $node cilium.io/ci-node=k8s$index --overwrite
    index=$((index+1))
done

echo "adding node registry as trusted"
helm template registry-adder "${test_dir}/k8sT/manifests/registry-adder-gke" --set IP="$(${test_dir}/print-node-ip.sh)" > "${script_dir}/registry-adder.yaml"
kubectl apply -f "${script_dir}/registry-adder.yaml"
