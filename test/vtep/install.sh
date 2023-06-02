#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

#Please refer https://docs.cilium.io/en/stable/installation/kind/

# 1 create kind cluster
kind create cluster --config=kind-cluster.yaml

# 2 install cilium

helm repo add cilium https://helm.cilium.io/

# docker pull the image and load in kind
docker pull cilium/cilium:<cilium version>
kind load docker-image cilium/cilium:<cilium version>

helm install cilium cilium/cilium --version <cilium version> \
   --namespace kube-system \
   --set vtep.enabled=true \
   --set vtep.endpoint="172.18.0.1" \
   --set vtep.cidr="10.1.5.0/24" \
   --set vtep.mask="255.255.255.0" \
   --set vtep.mac="00:50:56:A0:7D:D8"

# 3 deploy busybox on kind control plaine node

kubectl label node kind-control-plane  dedicated=master
kubectl taint nodes --all node-role.kubernetes.io/master-

kubectl apply -f busybox-master.yaml

# 4 deploy vxlan-responder systemd service, note change
#   change the bridge interface name in vxlan-responder.py
#   to sniff

echo "Enabling vxlan-responder.service by default in systemd..." >&2
cp vxlan-responder.service /etc/systemd/system/
cp vxlan-responder.py /usr/local/bin/
systemctl enable vxlan-responder.service
systemctl start vxlan-responder.service

