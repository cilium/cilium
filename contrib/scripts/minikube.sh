#!/bin/bash

set -eux

export MINIKUBE_NETWORK_PLUGIN="cni"
export MINIKUBE_EXTRA_CONFIG="kubelet.network-plugin=cni"
export MINIKUBE_MEMORY=5120
unset CONTAINER_ENGINE

minikube start
# TODO(mrostecki): Support cri-o and buildah.
eval $(minikube docker-env)

make docker-images-all DOCKER_IMAGE_TAG=dev

cp "install/kubernetes/quick-install.yaml" /tmp/cilium-minikube.yaml

sed -i 's|latest|dev|g' /tmp/cilium-minikube.yaml
sed -i 's|docker.io/||g' /tmp/cilium-minikube.yaml
sed -i 's|imagePullPolicy: Always|imagePullPolicy: Never|g' /tmp/cilium-minikube.yaml

kubectl create -f /tmp/cilium-minikube.yaml
