#!/usr/bin/env bash

PS4='+[\t] '
set -eux

export LC_NUMERIC=C

IMG_OWNER=${1:-cilium}
IMG_TAG=${2:-latest}
IMG_NAME=${3:-cilium-ci}
IMG_REPO=${4:-quay.io}

# For local testing, run 'make kind kind-image' and then
# sudo ./test.sh cilium local cilium-dev localhost:5000

###########
#  SETUP  #
###########

BUILDER_IMAGE="quay.io/cilium/cilium-builder:719132b42fff53994dc9bf9b98fddce9f613c828"
declare -a sources

# bpf_xdp_veth_host is a dummy XDP program which is going to be attached to LB
# node's veth pair end in the host netns. When bpf_xdp, which is attached in
# the container netns, forwards a LB request with XDP_TX, the request needs to
# be picked in the host netns by a NAPI handler. To register the handler, we
# attach the dummy program.
sources[0]=bpf_xdp_veth_host.c

# The worker (aka backend node) will receive IPIP packets from the LB node.
# To decapsulate the packets instead of creating an ipip dev which would
# complicate network setup, we will attach the following program which
# terminates the tunnel.
# The program is taken from the Linux kernel selftests.
sources[1]=test_tc_tunnel.c

for src in ${sources[*]}; do
    docker run --rm -v "$PWD/../../:/work" "$BUILDER_IMAGE" \
      clang -O2 -Wall --target=bpf -nostdinc -I/work/bpf/include -I/work/bpf \
        -c "/work/test/l4lb/$src" -o "/work/test/l4lb/${src%.c}.o"
done

# With Docker-in-Docker we create two nodes:
#
# * "lb-node" runs cilium in the LB-only mode.
# * "nginx" runs the nginx server.

docker rm -f nginx lb-node || true
docker network rm cilium-l4lb || true

docker network create cilium-l4lb
docker run --privileged --name lb-node -d \
    --network cilium-l4lb -v /lib/modules:/lib/modules \
    docker:dind
docker run --name nginx -d --network cilium-l4lb nginx

# Create additional veth pair which is going to be used to test XDP_REDIRECT.
ip l a l4lb-veth0 type veth peer l4lb-veth1
SECOND_LB_NODE_IP=3.3.3.2
ip a a "3.3.3.1/24" dev l4lb-veth0
CONTROL_PLANE_PID=$(docker inspect lb-node -f '{{ .State.Pid }}')
ip l s dev l4lb-veth1 netns $CONTROL_PLANE_PID
ip l s dev l4lb-veth0 up
nsenter -t $CONTROL_PLANE_PID -n /bin/sh -c "\
    ip a a "${SECOND_LB_NODE_IP}/24" dev l4lb-veth1 && \
    ip l s dev l4lb-veth1 up"

# Wait until Docker is ready in the lb-node node
while ! docker exec -t lb-node docker ps >/dev/null; do sleep 1; done

# Install Cilium as standalone L4LB
docker exec -t lb-node mount bpffs /sys/fs/bpf -t bpf

# Pull the image to the host and push it to the lb-node to allow
# use of locally built images.
docker image inspect ${IMG_REPO}/${IMG_OWNER}/${IMG_NAME}:${IMG_TAG} &> /dev/null || \
  docker pull ${IMG_REPO}/${IMG_OWNER}/${IMG_NAME}:${IMG_TAG}

docker save ${IMG_REPO}/${IMG_OWNER}/${IMG_NAME}:${IMG_TAG} | \
  docker exec -i lb-node docker load

docker exec -t lb-node \
  docker run --name cilium-lb -td \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /lib/modules:/lib/modules \
    --privileged=true \
    --network=host \
    ${IMG_REPO}/${IMG_OWNER}/${IMG_NAME}:${IMG_TAG} \
    cilium-agent \
    --enable-ipv4=true \
    --enable-ipv6=false \
    --datapath-mode=lb-only \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=native \
    --bpf-lb-mode=dsr \
    --devices="eth0,l4lb-veth1" \
    --direct-routing-device=eth0

IFIDX=$(docker exec -i lb-node \
    /bin/sh -c 'echo $(( $(ip -o l show eth0 | awk "{print $1}" | cut -d: -f1) ))')
LB_VETH_HOST=$(ip -o l | grep "if$IFIDX" | awk '{print $2}' | cut -d@ -f1)
ip l set dev $LB_VETH_HOST xdp obj bpf_xdp_veth_host.o
ip l set dev l4lb-veth0 xdp obj bpf_xdp_veth_host.o

# Disable TX and RX csum offloading, as veth does not support it. Otherwise,
# the forwarded packets by the LB to the worker node will have invalid csums.
ethtool -K $LB_VETH_HOST rx off tx off
ethtool -K l4lb-veth0 rx off tx off

NGINX_PID=$(docker inspect nginx -f '{{ .State.Pid }}')
WORKER_IP=$(nsenter -t $NGINX_PID -n ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1)
WORKER_MAC=$(nsenter -t $NGINX_PID -n ip -o l show dev eth0 | grep -oP '(?<=link/ether )[^ ]+')

# Install BPF program to terminate encapsulated packets coming from the LB
nsenter -t $NGINX_PID -n /bin/sh -c \
    'tc qdisc add dev eth0 clsact && tc filter add dev eth0 ingress bpf direct-action object-file ./test_tc_tunnel.o section decap'

# Wait until Cilium is ready
while ! docker exec -t lb-node docker exec -t cilium-lb cilium-dbg status; do sleep 1; done

##########
#  TEST  #
##########

LB_VIP="10.0.0.2"

nsenter -t $(docker inspect nginx -f '{{ .State.Pid }}') -n /bin/sh -c \
    "ip a a dev eth0 ${LB_VIP}/32"

# Check that empty list works
docker exec -t lb-node docker exec -t cilium-lb \
    cilium-dbg service list

docker exec -t lb-node docker exec -t cilium-lb \
    cilium-dbg service update \
      --frontend "${LB_VIP}:80:TCP" \
      --backends "${WORKER_IP}:80" \
      --k8s-node-port

# Validate get & list
docker exec -t lb-node docker exec -t cilium-lb \
    cilium-dbg service get "${LB_VIP}:80:TCP" | grep "^${LB_VIP}:80:TCP"
docker exec -t lb-node docker exec -t cilium-lb \
    cilium-dbg service list | grep "^${LB_VIP}:80:TCP"

LB_NODE_IP=$(docker exec lb-node ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1)
ip r a "${LB_VIP}/32" via "$LB_NODE_IP"

# Add the neighbor entry for the nginx node to avoid the LB failing to forward
# the requests due to the FIB lookup drops (nsenter, as busybox iproute2
# doesn't support neigh entries creation).
nsenter -t $CONTROL_PLANE_PID -n ip neigh add ${WORKER_IP} dev eth0 lladdr ${WORKER_MAC}

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

# Set nginx to maintenance
docker exec -t lb-node docker exec -t cilium-lb \
    cilium-dbg service update \
      --frontend "${LB_VIP}:80:TCP" \
      --backends "${WORKER_IP}:80" \
      --backend-weights "0" \
      --k8s-node-port

# Do not stop on error
set +e
# Issue 10 requests to LB (with 500ms timeout) which are expected to timeout
for i in $(seq 1 10); do
    curl -o /dev/null -m 0.5 "${LB_VIP}:80"
    # code 28 - Operation timeout
    if [ ! "$?" -eq 28 ]; then
        exit -1;
    fi
done
set -e

# Delete the frontend
docker exec -t lb-node docker exec -t cilium-lb \
    cilium-dbg service delete "${LB_VIP}:80:TCP"

# Validate that it's gone
docker exec -t lb-node docker exec -t cilium-lb \
    cilium-dbg service get "${LB_VIP}:80:TCP" || true
docker exec -t lb-node docker exec -t cilium-lb \
    cilium-dbg service list | grep "^${LB_VIP}:80:TCP" && false

# Cleanup
set +e
docker rm -f lb-node
docker rm -f nginx
docker network rm cilium-l4lb
