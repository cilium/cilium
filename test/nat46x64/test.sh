#!/usr/bin/env bash

PS4='+[\t] '
set -eux

IMG_OWNER=${1:-cilium}
IMG_TAG=${2:-latest}
CILIUM_EXEC="docker exec -t lb-node docker exec -t cilium-lb"

function cilium_install {
    docker exec -t lb-node docker rm -f cilium-lb || true
    docker exec -t lb-node \
        docker run --name cilium-lb -td \
            -v /sys/fs/bpf:/sys/fs/bpf \
            -v /lib/modules:/lib/modules \
            --privileged=true \
            --network=host \
            quay.io/${IMG_OWNER}/cilium-ci:${IMG_TAG} \
            cilium-agent \
            --enable-ipv4=true \
            --enable-ipv6=true \
            --devices=eth0 \
            --datapath-mode=lb-only \
            "$@"
    while ! ${CILIUM_EXEC} cilium status; do sleep 3; done
    sleep 1
}

# With Docker-in-Docker we create two nodes:
#
# * "lb-node" runs cilium in the LB-only mode.
# * "nginx" runs the nginx server.

docker network create --subnet="172.12.42.0/24,2001:db8:1::/64" --ipv6 cilium-l4lb
docker run --privileged --name lb-node -d \
    --network cilium-l4lb -v /lib/modules:/lib/modules \
    docker:dind
docker exec -t lb-node mount bpffs /sys/fs/bpf -t bpf
docker run --name nginx -d --network cilium-l4lb nginx

# Wait until Docker is ready in the lb-node node
while ! docker exec -t lb-node docker ps >/dev/null; do sleep 1; done

# Install Cilium as standalone L4LB (tc/Maglev/SNAT)
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=disabled \
    --bpf-lb-mode=snat

# Disable TX and RX csum offloading, as veth does not support it. Otherwise,
# the forwarded packets by the LB to the worker node will have invalid csums.
IFIDX=$(docker exec -i lb-node \
    /bin/sh -c 'echo $(( $(ip -o l show eth0 | awk "{print $1}" | cut -d: -f1) ))')
LB_VETH_HOST=$(ip -o l | grep "if$IFIDX" | awk '{print $2}' | cut -d@ -f1)
ethtool -K $LB_VETH_HOST rx off tx off

NGINX_PID=$(docker inspect nginx -f '{{ .State.Pid }}')
WORKER_IP4=$(nsenter -t $NGINX_PID -n ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
WORKER_IP6=$(nsenter -t $NGINX_PID -n ip -o -6 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
WORKER_MAC=$(nsenter -t $NGINX_PID -n ip -o l show dev eth0 | grep -oP '(?<=link/ether )[^ ]+')

# NAT 4->6 test suite (services)
################################

LB_VIP="10.0.0.4"

${CILIUM_EXEC} \
    cilium service update --id 1 --frontend "${LB_VIP}:80" --backends "[${WORKER_IP6}]:80" --k8s-node-port

SVC_BEFORE=$(${CILIUM_EXEC} cilium service list)

${CILIUM_EXEC} cilium bpf lb list

MAG_V4=$(${CILIUM_EXEC} cilium bpf lb maglev list -o=jsonpath='{.\[1\]/v4}' | tr -d '\r')
MAG_V6=$(${CILIUM_EXEC} cilium bpf lb maglev list -o=jsonpath='{.\[1\]/v6}' | tr -d '\r')
if [ ! -z "$MAG_V4" -o -z "$MAG_V6" ]; then
	echo "Invalid content of Maglev table!"
	${CILIUM_EXEC} cilium bpf lb maglev list
	exit 1
fi

LB_NODE_IP=$(docker exec -t lb-node ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip r a "${LB_VIP}/32" via "$LB_NODE_IP"

# Add the neighbor entry for the nginx node to avoid the LB failing to forward
# the requests due to the FIB lookup drops (nsenter, as busybox iproute2
# doesn't support neigh entries creation).
CONTROL_PLANE_PID=$(docker inspect lb-node -f '{{ .State.Pid }}')
nsenter -t $CONTROL_PLANE_PID -n ip neigh add ${WORKER_IP6} dev eth0 lladdr ${WORKER_MAC}

# Issue 10 requests to LB
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80" || (echo "Failed $i"; exit -1)
done

# Install Cilium as standalone L4LB: XDP/Maglev/SNAT
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=native \
    --bpf-lb-mode=snat

# Check that restoration went fine. Note that we currently cannot do runtime test
# as veth + XDP is broken when switching protocols. Needs something bare metal.
SVC_AFTER=$(${CILIUM_EXEC} cilium service list)

${CILIUM_EXEC} cilium bpf lb list

[ "$SVC_BEFORE" != "$SVC_AFTER" ] && exit 1

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=disabled \
    --bpf-lb-mode=snat

# Check that curl still works after restore
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80" || (echo "Failed $i"; exit -1)
done

# Install Cilium as standalone L4LB: tc/Random/SNAT
cilium_install \
    --bpf-lb-algorithm=random \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=disabled \
    --bpf-lb-mode=snat

# Check that curl also works for random selection
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80" || (echo "Failed $i"; exit -1)
done

# Add another IPv6->IPv6 service and reuse backend

LB_ALT="fd00:dead:beef:15:bad::1"

${CILIUM_EXEC} \
    cilium service update --id 2 --frontend "[${LB_ALT}]:80" --backends "[${WORKER_IP6}]:80" --k8s-node-port

${CILIUM_EXEC} cilium service list
${CILIUM_EXEC} cilium bpf lb list

LB_NODE_IP=$(docker exec lb-node ip -o -6 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip -6 r a "${LB_ALT}/128" via "$LB_NODE_IP"

# Issue 10 requests to LB1
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80" || (echo "Failed $i"; exit -1)
done

# Issue 10 requests to LB2
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_ALT}]:80" || (echo "Failed $i"; exit -1)
done

# Check if restore for both is proper and that this also works
# under nat46x64-gateway enabled.

# Install Cilium as standalone L4LB: tc/Maglev/SNAT/GW
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=disabled \
    --bpf-lb-mode=snat \
    --enable-nat46x64-gateway=true

# Issue 10 requests to LB1
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80" || (echo "Failed $i"; exit -1)
done

# Issue 10 requests to LB2
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_ALT}]:80" || (echo "Failed $i"; exit -1)
done

${CILIUM_EXEC} cilium service delete 1
${CILIUM_EXEC} cilium service delete 2
nsenter -t $CONTROL_PLANE_PID -n ip neigh del ${WORKER_IP6} dev eth0

# NAT 6->4 test suite (services)
################################

LB_VIP="fd00:cafe::1"

${CILIUM_EXEC} \
    cilium service update --id 1 --frontend "[${LB_VIP}]:80" --backends "${WORKER_IP4}:80" --k8s-node-port

SVC_BEFORE=$(${CILIUM_EXEC} cilium service list)

${CILIUM_EXEC} cilium bpf lb list

MAG_V4=$(${CILIUM_EXEC} cilium bpf lb maglev list -o=jsonpath='{.\[1\]/v4}' | tr -d '\r')
MAG_V6=$(${CILIUM_EXEC} cilium bpf lb maglev list -o=jsonpath='{.\[1\]/v6}' | tr -d '\r')
if [ ! -z "$MAG_V4" -o -z "$MAG_V6" ]; then
	echo "Invalid content of Maglev table!"
	${CILIUM_EXEC} cilium bpf lb maglev list
	exit 1
fi

LB_NODE_IP=$(docker exec -t lb-node ip -o -6 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip -6 r a "${LB_VIP}/128" via "$LB_NODE_IP"

# Add the neighbor entry for the nginx node to avoid the LB failing to forward
# the requests due to the FIB lookup drops (nsenter, as busybox iproute2
# doesn't support neigh entries creation).
CONTROL_PLANE_PID=$(docker inspect lb-node -f '{{ .State.Pid }}')
nsenter -t $CONTROL_PLANE_PID -n ip neigh add ${WORKER_IP4} dev eth0 lladdr ${WORKER_MAC}

# Issue 10 requests to LB
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80" || (echo "Failed $i"; exit -1)
done

# Install Cilium as standalone L4LB: XDP/Maglev/SNAT
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=native \
    --bpf-lb-mode=snat

# Check that restoration went fine. Note that we currently cannot do runtime test
# as veth + XDP is broken when switching protocols. Needs something bare metal.
SVC_AFTER=$(${CILIUM_EXEC} cilium service list)

${CILIUM_EXEC} cilium bpf lb list

[ "$SVC_BEFORE" != "$SVC_AFTER" ] && exit 1

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=disabled \
    --bpf-lb-mode=snat

# Check that curl still works after restore
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80" || (echo "Failed $i"; exit -1)
done

# Install Cilium as standalone L4LB: tc/Random/SNAT
cilium_install \
    --bpf-lb-algorithm=random \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=disabled \
    --bpf-lb-mode=snat

# Check that curl also works for random selection
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80" || (echo "Failed $i"; exit -1)
done

# Add another IPv4->IPv4 service and reuse backend

LB_ALT="10.0.0.8"

${CILIUM_EXEC} \
    cilium service update --id 2 --frontend "${LB_ALT}:80" --backends "${WORKER_IP4}:80" --k8s-node-port

${CILIUM_EXEC} cilium service list
${CILIUM_EXEC} cilium bpf lb list

LB_NODE_IP=$(docker exec -t lb-node ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip r a "${LB_ALT}/32" via "$LB_NODE_IP"

# Issue 10 requests to LB1
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80" || (echo "Failed $i"; exit -1)
done

# Issue 10 requests to LB2
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_ALT}:80" || (echo "Failed $i"; exit -1)
done

# Check if restore for both is proper and that this also works
# under nat46x64-gateway enabled.

# Install Cilium as standalone L4LB: tc/Maglev/SNAT/GW
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=disabled \
    --bpf-lb-mode=snat \
    --enable-nat46x64-gateway=true

# Issue 10 requests to LB1
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80" || (echo "Failed $i"; exit -1)
done

# Issue 10 requests to LB2
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_ALT}:80" || (echo "Failed $i"; exit -1)
done

${CILIUM_EXEC} cilium service delete 1
${CILIUM_EXEC} cilium service delete 2
nsenter -t $CONTROL_PLANE_PID -n ip neigh del ${WORKER_IP4} dev eth0

# Misc compilation tests
########################

# Install Cilium as standalone L4LB & NAT46/64 GW: tc
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=disabled \
    --bpf-lb-mode=snat \
    --enable-nat46x64-gateway=true

# Install Cilium as standalone L4LB & NAT46/64 GW: XDP
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=native \
    --bpf-lb-mode=snat \
    --enable-nat46x64-gateway=true

# Install Cilium as standalone L4LB & NAT46/64 GW: restore
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=disabled \
    --bpf-lb-mode=snat

# NAT test suite & PCAP recorder
################################

# Install Cilium as standalone L4LB: XDP/Maglev/SNAT/Recorder
cilium_install \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-dsr-dispatch=ipip \
    --bpf-lb-acceleration=native \
    --bpf-lb-mode=snat \
    --enable-recorder=true

# Trigger recompilation with 32 IPv4 filter masks
${CILIUM_EXEC} \
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
${CILIUM_EXEC} \
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

${CILIUM_EXEC} cilium recorder list
${CILIUM_EXEC} cilium bpf recorder list
${CILIUM_EXEC} cilium recorder delete 1
${CILIUM_EXEC} cilium recorder delete 2
${CILIUM_EXEC} cilium recorder list

# cleanup
docker rm -f lb-node
docker rm -f nginx
docker network rm cilium-l4lb

echo "YAY!"
