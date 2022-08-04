#!/bin/bash

PS4='+[\t] '
set -eux

IMG_OWNER=${1:-cilium}
IMG_TAG=${2:-latest}
HELM_CHART_DIR=${3:-/vagrant/install/kubernetes/cilium}

kind create cluster --config kind-config.yaml --image=brb0/kindest-node:v1.23.3-ubuntu-22.04

API_SERVER_IP=$(docker inspect kind-control-plane -f '{{ .NetworkSettings.Networks.kind.IPAddress }}')

helm install cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --set debug.enabled=true \
    --set image.repository="quay.io/${IMG_OWNER}/cilium-ci" \
    --set image.tag="${IMG_TAG}" \
    --set image.useDigest=false \
    --set image.pullPolicy=IfNotPresent \
    --set kubeProxyReplacement=strict \
    --set k8sServiceHost="${API_SERVER_IP}" \
    --set k8sServicePort=6443

kubectl run nginx --image=nginx
kubectl expose pod nginx --port=80 --type=NodePort
sleep 60
NODEPORT=$(kubectl get svc nginx -o=jsonpath='{.spec.ports[].nodePort}')
curl "http://${API_SERVER_IP}:${NODEPORT}"

for cont in kind-control-plane kind-worker kind-worker2; do
    docker exec ${cont} curl "http://${API_SERVER_IP}:${NODEPORT}"
done

echo "YAY!"

kind delete cluster
