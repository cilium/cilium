#!/bin/bash

PS4='+[\t] '
set -eux

IMG_OWNER=${1:-cilium}
IMG_TAG=${2:-latest}
HELM_CHART_DIR=${3:-/vagrant/install/kubernetes/cilium}

# With Kind we create two nodes cluster:
#
# * "kind-control-plane" runs cilium in the LB-only mode.
# * "kind-worker" runs the nginx server.
#
# The LB cilium does not connect to the kube-apiserver. For now we use Kind
# just to create Docker-in-Docker containers.
kind create cluster --config kind-config.yaml

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
helm install cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --set debug.enabled=true \
    --set image.repository="quay.io/${IMG_OWNER}/cilium-ci" \
    --set image.tag="${IMG_TAG}" \
    --set image.useDigest=false \
    --set image.pullPolicy=IfNotPresent \
    --set operator.enabled=false \
    --set loadBalancer.standalone=true \
    --set loadBalancer.algorithm=maglev \
    --set loadBalancer.mode=snat \
    --set loadBalancer.acceleration=disabled \
    --set devices='{eth0}' \
    --set ipv4.enabled=true \
    --set ipv6.enabled=true \
    --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key="kubernetes.io/hostname" \
    --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=In \
    --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]=kind-control-plane

# Disable TX and RX csum offloading, as veth does not support it. Otherwise,
# the forwarded packets by the LB to the worker node will have invalid csums.
IFIDX=$(docker exec -i kind-control-plane \
    /bin/sh -c 'echo $(( $(ip -o l show eth0 | awk "{print $1}" | cut -d: -f1) ))')
LB_VETH_HOST=$(ip -o l | grep "if$IFIDX" | awk '{print $2}' | cut -d@ -f1)
ethtool -K $LB_VETH_HOST rx off tx off

docker exec kind-worker /bin/sh -c 'apt-get update && apt-get install -y nginx && systemctl start nginx'
WORKER_IP6=$(docker exec kind-worker ip -o -6 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
WORKER_IP4=$(docker exec kind-worker ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# NAT 4->6 test suite
#####################

LB_VIP="10.0.0.4"

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
    cilium service update --id 1 --frontend "${LB_VIP}:80" --backends "[${WORKER_IP6}]:80" --k8s-node-port

SVC_BEFORE=$(kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list)

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

LB_NODE_IP=$(docker exec kind-control-plane ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip r a "${LB_VIP}/32" via "$LB_NODE_IP"

# Issue 10 requests to LB
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80"
done

# Install Cilium as standalone L4LB: XDP/Maglev/SNAT
helm upgrade cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.acceleration=native
kubectl -n kube-system delete pod -l k8s-app=cilium

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Check that restoration went fine. Note that we currently cannot do runtime test
# as veth + XDP is broken when switching protocols. Needs something bare metal.
CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
SVC_AFTER=$(kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list)

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

[ "$SVC_BEFORE" != "$SVC_AFTER" ] && exit 1

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
helm upgrade cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.acceleration=disabled
kubectl -n kube-system delete pod -l k8s-app=cilium

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Check that curl still works after restore
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80"
done

# Install Cilium as standalone L4LB: tc/Random/SNAT
helm upgrade cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.algorithm=random
kubectl -n kube-system delete pod -l k8s-app=cilium

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Check that curl also works for random selection
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80"
done

# Add another IPv6->IPv6 service and reuse backend

LB_ALT="fd00:dead:beef:15:bad::1"

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
    cilium service update --id 2 --frontend "[${LB_ALT}]:80" --backends "[${WORKER_IP6}]:80" --k8s-node-port

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

LB_NODE_IP=$(docker exec kind-control-plane ip -o -6 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip -6 r a "${LB_ALT}/128" via "$LB_NODE_IP"

# Issue 10 requests to LB1
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80"
done

# Issue 10 requests to LB2
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_ALT}]:80"
done

# Check if restore for both is proper

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
helm upgrade cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.algorithm=maglev
kubectl -n kube-system delete pod -l k8s-app=cilium

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Issue 10 requests to LB1
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80"
done

# Issue 10 requests to LB2
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_ALT}]:80"
done

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service delete 1
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service delete 2

# NAT 6->4 test suite
#####################

LB_VIP="fd00:cafe::1"

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
    cilium service update --id 1 --frontend "[${LB_VIP}]:80" --backends "${WORKER_IP4}:80" --k8s-node-port

SVC_BEFORE=$(kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list)

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

LB_NODE_IP=$(docker exec kind-control-plane ip -o -6 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip -6 r a "${LB_VIP}/128" via "$LB_NODE_IP"

# Issue 10 requests to LB
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80"
done

# Install Cilium as standalone L4LB: XDP/Maglev/SNAT
helm upgrade cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.acceleration=native
kubectl -n kube-system delete pod -l k8s-app=cilium

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Check that restoration went fine. Note that we currently cannot do runtime test
# as veth + XDP is broken when switching protocols. Needs something bare metal.
CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
SVC_AFTER=$(kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list)

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

[ "$SVC_BEFORE" != "$SVC_AFTER" ] && exit 1

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
helm upgrade cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.acceleration=disabled
kubectl -n kube-system delete pod -l k8s-app=cilium

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Check that curl still works after restore
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80"
done

# Install Cilium as standalone L4LB: tc/Random/SNAT
helm upgrade cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.algorithm=random
kubectl -n kube-system delete pod -l k8s-app=cilium

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Check that curl also works for random selection
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80"
done

# Add another IPv4->IPv4 service and reuse backend

LB_ALT="10.0.0.8"

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
    cilium service update --id 2 --frontend "${LB_ALT}:80" --backends "${WORKER_IP4}:80" --k8s-node-port

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

LB_NODE_IP=$(docker exec kind-control-plane ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip r a "${LB_ALT}/32" via "$LB_NODE_IP"

# Issue 10 requests to LB1
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80"
done

# Issue 10 requests to LB2
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_ALT}:80"
done

# Check if restore for both is proper

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
helm upgrade cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.algorithm=maglev
kubectl -n kube-system delete pod -l k8s-app=cilium

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Issue 10 requests to LB1
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80"
done

# Issue 10 requests to LB2
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_ALT}:80"
done

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service delete 1
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service delete 2

# NAT test suite & PCAP recorder
################################

# Install Cilium as standalone L4LB: XDP/Maglev/SNAT/Recorder
helm upgrade cilium ${HELM_CHART_DIR} \
    --wait \
    --namespace kube-system \
    --reuse-values \
    -f recorder-config.yaml \
    --set loadBalancer.algorithm=maglev \
    --set loadBalancer.acceleration=native
kubectl -n kube-system delete pod -l k8s-app=cilium

kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Trigger recompilation with 32 IPv4 filter masks
CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
    cilium recorder update --id 1 --caplen 100 \
        --filters="2.2.2.2/0 0 1.1.1.1/32 80 TCP,\
2.2.2.2/1 0 1.1.1.1/32 80 TCP,\
2.2.2.2/2 0 1.1.1.1/31 80 TCP,\
2.2.2.2/3 0 1.1.1.1/30 80 TCP,\
2.2.2.2/4 0 1.1.1.1/29 80 TCP,\
2.2.2.2/5 0 1.1.1.1/28 80 TCP,\
2.2.2.2/6 0 1.1.1.1/27 80 TCP,\
2.2.2.2/7 0 1.1.1.1/26 80 TCP,\
2.2.2.2/8 0 1.1.1.1/25 80 TCP,\
2.2.2.2/9 0 1.1.1.1/24 80 TCP,\
2.2.2.2/10 0 1.1.1.1/23 80 TCP,\
2.2.2.2/11 0 1.1.1.1/22 80 TCP,\
2.2.2.2/12 0 1.1.1.1/21 80 TCP,\
2.2.2.2/13 0 1.1.1.1/20 80 TCP,\
2.2.2.2/14 0 1.1.1.1/19 80 TCP,\
2.2.2.2/15 0 1.1.1.1/18 80 TCP,\
2.2.2.2/16 0 1.1.1.1/17 80 TCP,\
2.2.2.2/17 0 1.1.1.1/16 80 TCP,\
2.2.2.2/18 0 1.1.1.1/15 80 TCP,\
2.2.2.2/19 0 1.1.1.1/14 80 TCP,\
2.2.2.2/20 0 1.1.1.1/13 80 TCP,\
2.2.2.2/21 0 1.1.1.1/12 80 TCP,\
2.2.2.2/22 0 1.1.1.1/11 80 TCP,\
2.2.2.2/23 0 1.1.1.1/10 80 TCP,\
2.2.2.2/24 0 1.1.1.1/9 80 TCP,\
2.2.2.2/25 0 1.1.1.1/8 80 TCP,\
2.2.2.2/26 0 1.1.1.1/7 80 TCP,\
2.2.2.2/27 0 1.1.1.1/6 80 TCP,\
2.2.2.2/28 0 1.1.1.1/5 80 TCP,\
2.2.2.2/29 0 1.1.1.1/4 80 TCP,\
2.2.2.2/30 0 1.1.1.1/3 80 TCP,\
2.2.2.2/31 0 1.1.1.1/2 80 TCP,\
2.2.2.2/32 0 1.1.1.1/1 80 TCP,\
2.2.2.2/32 0 1.1.1.1/0 80 TCP"

# Trigger recompilation with 32 IPv6 filter masks
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
    cilium recorder update --id 2 --caplen 100 \
        --filters="f00d::1/0 80 cafe::/128 0 UDP,\
f00d::1/1 80 cafe::/127 0 UDP,\
f00d::1/2 80 cafe::/126 0 UDP,\
f00d::1/3 80 cafe::/125 0 UDP,\
f00d::1/4 80 cafe::/124 0 UDP,\
f00d::1/5 80 cafe::/123 0 UDP,\
f00d::1/6 80 cafe::/122 0 UDP,\
f00d::1/7 80 cafe::/121 0 UDP,\
f00d::1/8 80 cafe::/120 0 UDP,\
f00d::1/9 80 cafe::/119 0 UDP,\
f00d::1/10 80 cafe::/118 0 UDP,\
f00d::1/11 80 cafe::/117 0 UDP,\
f00d::1/12 80 cafe::/116 0 UDP,\
f00d::1/13 80 cafe::/115 0 UDP,\
f00d::1/14 80 cafe::/114 0 UDP,\
f00d::1/15 80 cafe::/113 0 UDP,\
f00d::1/16 80 cafe::/112 0 UDP,\
f00d::1/17 80 cafe::/111 0 UDP,\
f00d::1/18 80 cafe::/110 0 UDP,\
f00d::1/19 80 cafe::/109 0 UDP,\
f00d::1/20 80 cafe::/108 0 UDP,\
f00d::1/21 80 cafe::/107 0 UDP,\
f00d::1/22 80 cafe::/106 0 UDP,\
f00d::1/23 80 cafe::/105 0 UDP,\
f00d::1/24 80 cafe::/104 0 UDP,\
f00d::1/25 80 cafe::/103 0 UDP,\
f00d::1/26 80 cafe::/102 0 UDP,\
f00d::1/27 80 cafe::/101 0 UDP,\
f00d::1/28 80 cafe::/100 0 UDP,\
f00d::1/29 80 cafe::/99 0 UDP,\
f00d::1/30 80 cafe::/98 0 UDP,\
f00d::1/31 80 cafe::/97 0 UDP,\
f00d::1/32 80 cafe::/96 0 UDP,\
f00d::1/32 80 cafe::/0 0 UDP"

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium recorder list
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf recorder list
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium recorder delete 1
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium recorder delete 2
kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium recorder list

echo "YAY!"
