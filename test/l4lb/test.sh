#!/bin/bash

PS4='+[\t] '
set -eux

IMG_OWNER=${1:-cilium}
IMG_TAG=${2:-latest}
HELM_CHART_DIR=${3:-/vagrant/install/kubernetes/cilium}

###########
#  SETUP  #
###########

# bpf_xdp_veth_host is a dummy XDP program which is going to be attached to LB
# node's veth pair end in the host netns. When bpf_xdp, which is attached in
# the container netns, forwards a LB request with XDP_TX, the request needs to
# be picked in the host netns by a NAPI handler. To register the handler, we
# attach the dummy program.
clang -O2 -Wall -target bpf -c bpf_xdp_veth_host.c -o bpf_xdp_veth_host.o

# The worker (aka backend node) will receive IPIP packets from the LB node.
# To decapsulate the packets instead of creating an ipip dev which would
# complicate network setup, we will attach the following program which
# terminates the tunnel.
# The program is taken from the Linux kernel selftests.
clang -O2 -Wall -target bpf -c test_tc_tunnel.c -o test_tc_tunnel.o

# With Kind we create two nodes cluster:
#
# * "kind-control-plane" runs cilium in the LB-only mode.
# * "kind-worker" runs the nginx server.
#
# The LB cilium does not connect to the kube-apiserver. For now we use Kind
# just to create Docker-in-Docker containers.
kind create cluster --config kind-config.yaml

# Create additional veth pair which is going to be used to test XDP_REDIRECT.
ip l a l4lb-veth0 type veth peer l4lb-veth1
SECOND_LB_NODE_IP=3.3.3.2
ip a a "3.3.3.1/24" dev l4lb-veth0
CONTROL_PLANE_PID=$(docker inspect kind-control-plane -f '{{ .State.Pid }}')
ip l s dev l4lb-veth1 netns $CONTROL_PLANE_PID
ip l s dev l4lb-veth0 up
nsenter -t $CONTROL_PLANE_PID -n /bin/sh -c "\
    ip a a "${SECOND_LB_NODE_IP}/24" dev l4lb-veth1 && \
    ip l s dev l4lb-veth1 up"

# Install Cilium as standalone L4LB
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
    --set loadBalancer.mode=dsr \
    --set loadBalancer.acceleration=native \
    --set loadBalancer.dsrDispatch=ipip \
    --set devices='{eth0,l4lb-veth1}' \
    --set nodePort.directRoutingDevice=eth0 \
    --set ipv6.enabled=false \
    --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key="kubernetes.io/hostname" \
    --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=In \
    --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]=kind-control-plane

IFIDX=$(docker exec -i kind-control-plane \
    /bin/sh -c 'echo $(( $(ip -o l show eth0 | awk "{print $1}" | cut -d: -f1) ))')
LB_VETH_HOST=$(ip -o l | grep "if$IFIDX" | awk '{print $2}' | cut -d@ -f1)
ip l set dev $LB_VETH_HOST xdp obj bpf_xdp_veth_host.o
ip l set dev l4lb-veth0 xdp obj bpf_xdp_veth_host.o

# Disable TX and RX csum offloading, as veth does not support it. Otherwise,
# the forwarded packets by the LB to the worker node will have invalid csums.
ethtool -K $LB_VETH_HOST rx off tx off
ethtool -K l4lb-veth0 rx off tx off

docker exec kind-worker /bin/sh -c 'apt-get update && apt-get install -y nginx && systemctl start nginx'
WORKER_IP=$(docker exec kind-worker ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1)
nsenter -t $(docker inspect kind-worker -f '{{ .State.Pid }}') -n /bin/sh -c \
    'tc qdisc add dev eth0 clsact && tc filter add dev eth0 ingress bpf direct-action object-file ./test_tc_tunnel.o section decap'

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system wait --for=condition=Ready pod "$CILIUM_POD_NAME" --timeout=5m

##########
#  TEST  #
##########

LB_VIP="10.0.0.2"

nsenter -t $(docker inspect kind-worker -f '{{ .State.Pid }}') -n /bin/sh -c \
    "ip a a dev eth0 ${LB_VIP}/32"

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
    cilium service update --id 1 --frontend "${LB_VIP}:80" --backends "${WORKER_IP}:80" --k8s-node-port

LB_NODE_IP=$(docker exec kind-control-plane ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1)
ip r a "${LB_VIP}/32" via "$LB_NODE_IP"

# Issue 10 requests to LB
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80" || (echo "Failed $i"; exit -1)
done

# Now steer the traffic to LB_VIP via the secondary device so that XDP_REDIRECT
# can be tested on the L4LB node
ip r replace "${LB_VIP}/32" via "$SECOND_LB_NODE_IP"

# Issue 10 requests to LB
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80" || (echo "Failed $i"; exit -1)
done

# Cleanup
kind delete cluster
