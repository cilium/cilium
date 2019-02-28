#!/bin/bash

set -eux

KUBERNETES_VERSION=${KUBERNETES_VERSION:-v1.13.2}

export MINIKUBE_NETWORK_PLUGIN="cni"
export MINIKUBE_EXTRA_CONFIG="kubelet.network-plugin=cni"
export MINIKUBE_MEMORY=5120
export MINIKUBE_KUBERNETES_VERSION="${KUBERNETES_VERSION}"
unset CONTAINER_ENGINE

minikube start
# TODO(mrostecki): Support cri-o and buildah.
eval $(minikube docker-env)

make docker-image DOCKER_IMAGE_TAG=dev

version="${KUBERNETES_VERSION:1}"
version_minor="${version%.*}"
cp "examples/kubernetes/${version_minor}/cilium-minikube.yaml" /tmp/cilium-minikube.yaml

sed -i 's|latest|dev|g' /tmp/cilium-minikube.yaml
sed -i 's|docker.io/||g' /tmp/cilium-minikube.yaml
sed -i 's|imagePullPolicy: Always|imagePullPolicy: Never|g' /tmp/cilium-minikube.yaml

kubectl create -f /tmp/cilium-minikube.yaml
