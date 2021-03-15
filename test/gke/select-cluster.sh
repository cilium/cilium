#!/bin/bash

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

project="cilium-ci"
# this is only needs to be set as some of gcloud commands requires it,
# but as this script uses resource URIs clusters in all locations are
# going to be discovered and used
region="us-west1"

set -e

locked=1

export KUBECONFIG="${script_dir}/gke-kubeconfig"

while [ $locked -ne 0 ]; do
    rm -f "${KUBECONFIG}"
    echo "selecting random cluster"
    for cluster_uri in $(gcloud container clusters list --project "${project}" --filter="name ~ ^cilium-ci-" --uri | sort -R); do

	echo "checking whether cluster ${cluster_uri} has any node pools"
	node_pools=$(gcloud container node-pools list --project "${project}" --region "${region}" --cluster "${cluster_uri}" --format="value(name)")
	if [ -z "${node_pools}" ]; then
		echo "no nodepools found, selecting another cluster"
		continue
	fi

	echo "checking whether cluster ${cluster_uri} is running"
	status=$(gcloud container clusters describe --project "${project}" --format="value(status)" "${cluster_uri}" --region="${region}")
	if [[ "$status" != "RUNNING"  ]] ; then
		echo "cluster status is $status , trying out another cluster"
		continue
	fi

	cluster_name=${cluster_uri##*/}
	echo "checking whether cluster ${cluster_uri} has a running operation"
	if gcloud container operations list | grep RUNNING | grep "${cluster_name}" ; then
		echo "cluster has an ongoing operation, trying out another cluster"
		continue
	fi


	echo "checking whether cluster ${cluster_uri} has node pools"
	node_pools=($(gcloud container node-pools list --project "${project}" --region "${region}" --cluster "${cluster_uri}" --format="value(name)"))
	if [ "${#node_pools[@]}" -ne 1 ] ; then
	  echo "expected 1 node pool, found ${#node_pools[@]}"
	  continue
	fi

	echo "getting kubeconfig for ${cluster_uri} (will store in ${KUBECONFIG})"
	gcloud container clusters get-credentials --project "${project}" --region "${region}" "${cluster_uri}"

	echo "acquiring cluster lock"
	set +e
	kubectl create namespace cilium-ci-lock
	kubectl create -f "${script_dir}/lock.yaml"

	kubectl annotate deployment -n cilium-ci-lock lock lock=1
	locked=$?
	echo $locked
	if [ -n "${BUILD_URL+x}" ] && [ $locked -eq 0 ] ; then
	    kubectl annotate deployment -n cilium-ci-lock lock --overwrite "jenkins-build-url=${BUILD_URL}"
	fi
	set -e
	if [ $locked -eq 0 ] ; then
	   break
	fi
    done
done

echo "lock acquired on cluster ${cluster_uri}"
echo "${cluster_uri}" > "${script_dir}/cluster-uri"
gcloud container clusters describe --project "${project}" --region "${region}" --format='value(name)' "${cluster_uri}" > "${script_dir}/cluster-name"
gcloud container clusters describe --project "${project}" --region "${region}" --format='value(currentMasterVersion)' "${cluster_uri}" \
  | sed -E 's/([0-9]+\.[0-9]+)\..*/\1/' | tr -d '\n' > "${script_dir}/cluster-version"
gcloud container clusters describe --project "${project}" --region "${region}" --format='value(clusterIpv4Cidr)' "${cluster_uri}" > "${script_dir}/cluster-cidr"

echo "cleaning cluster before tests"
"${script_dir}"/clean-cluster.sh

echo "scaling ${cluster_uri} to 2"
"${script_dir}"/resize-cluster.sh 2 "${cluster_uri}"

echo "labeling nodes"
index=1
for node in $(kubectl get nodes --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}');
do
    kubectl label node "$node" cilium.io/ci-node=k8s"$index" --overwrite
    index=$((index+1))
done
