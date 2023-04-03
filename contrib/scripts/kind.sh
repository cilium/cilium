#!/usr/bin/env bash

# Source: https://kind.sigs.k8s.io/docs/user/local-registry/

set -euo pipefail

default_controlplanes=1
default_workers=1
default_cluster_name=""
default_image=""
default_kubeproxy_mode="iptables"
default_ipfamily="ipv4"
default_network="kind-cilium"

PROG=${0}

xdp=false
if [ "${1:-}" = "--xdp" ]; then
  xdp=true
  shift
fi
readonly xdp

controlplanes="${1:-${CONTROLPLANES:=${default_controlplanes}}}"
workers="${2:-${WORKERS:=${default_workers}}}"
cluster_name="${3:-${CLUSTER_NAME:=${default_cluster_name}}}"
# IMAGE controls the K8s version as well (e.g. kindest/node:v1.11.10)
image="${4:-${IMAGE:=${default_image}}}"
kubeproxy_mode="${5:-${KUBEPROXY_MODE:=${default_kubeproxy_mode}}}"
ipfamily="${6:-${IPFAMILY:=${default_ipfamily}}}"

bridge_dev="br-${default_network}"
v6_prefix="fc00:c111::/64"
CILIUM_ROOT="$(git rev-parse --show-toplevel)"

usage() {
  echo "Usage: ${PROG} [--xdp] [control-plane node count] [worker node count] [cluster-name] [node image] [kube-proxy mode] [ip-family]"
}

have_kind() {
    [[ -n "$(command -v kind)" ]]
}

if ! have_kind; then
    echo "Please install kind first:"
    echo "  https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
fi

if [ ${#} -gt 6 ]; then
  usage
  exit 1
fi

if [[ "${controlplanes}" == "-h" || "${controlplanes}" == "--help" ]]; then
  usage
  exit 0
fi

# Registry will be localhost:5000
reg_name="kind-registry"
reg_port="5000"
running="$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"
if [[ "${running}" != "true" ]]; then
  retry_count=0
  while ! docker pull registry:2
  do
    retry_count=$((retry_count+1))
    if [[ "$retry_count" -ge 10 ]]; then
      echo "ERROR: 'docker pull registry:2' failed $retry_count times. Please make sure docker is running"
      exit 1
    fi
    echo "docker pull registry:2 failed. Sleeping for 1 second and trying again..."
    sleep 1
  done
  docker run \
    -d --restart=always -p "${reg_port}:5000" --name "${reg_name}" \
    registry:2
fi

kind_cmd="kind create cluster"

if [[ -n "${cluster_name}" ]]; then
  kind_cmd+=" --name ${cluster_name}"
fi
if [[ -n "${image}" ]]; then
  kind_cmd+=" --image ${image}"
fi

node_config() {
    local port="234$1$2"
    local max="$3"

    echo "  extraMounts:"
    echo "  - hostPath: $CILIUM_ROOT"
    echo "    containerPath: /home/vagrant/go/src/github.com/cilium/cilium"
    if [[ "${max}" -lt 10 ]]; then
        echo "  extraPortMappings:"
        echo "  - containerPort: 2345"
        echo "    hostPort: $port"
        echo "    listenAddress: \"127.0.0.1\""
        echo "    protocol: TCP"
    fi
}

control_planes() {
  for i in $(seq 1 "${controlplanes}"); do
    echo "- role: control-plane"
    node_config "0" "$i" "${controlplanes}"
  done
}

workers() {
  for i in $(seq 1 "${workers}"); do
    echo "- role: worker"
    node_config "1" "$i" "${workers}"
  done
}

# create a custom network so we can control the name of the bridge device.
# Inspired by https://github.com/kubernetes-sigs/kind/blob/6b58c9dfcbdb1b3a0d48754d043d59ca7073589b/pkg/cluster/internal/providers/docker/network.go#L149-L161
docker network create -d=bridge \
  -o "com.docker.network.bridge.enable_ip_masquerade=true" \
  -o "com.docker.network.bridge.name=${bridge_dev}" \
  --ipv6 --subnet "${v6_prefix}" \
  "${default_network}"

export KIND_EXPERIMENTAL_DOCKER_NETWORK="${default_network}"

# create a cluster with the local registry enabled in containerd
cat <<EOF | ${kind_cmd} --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
$(control_planes)
$(workers)
networking:
  disableDefaultCNI: true
  kubeProxyMode: ${kubeproxy_mode}
  ipFamily: ${ipfamily}
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:${reg_port}"]
EOF

if [ "${xdp}" = true ]; then
  if ! [ -f "${CILIUM_ROOT}/test/l4lb/bpf_xdp_veth_host.o" ]; then
    pushd "${CILIUM_ROOT}/test/l4lb/" > /dev/null
    clang -O2 -Wall -target bpf -c bpf_xdp_veth_host.c -o bpf_xdp_veth_host.o
    popd > /dev/null
  fi

  for ifc in /sys/class/net/"${bridge_dev}"/brif/*; do
    ifc="${ifc#"/sys/class/net/${bridge_dev}/brif/"}"

    # Attach a dummy XDP prog to the host side of the veth so that XDP_TX in the
    # pod side works.
    sudo ip link set dev "${ifc}" xdp obj "${CILIUM_ROOT}/test/l4lb/bpf_xdp_veth_host.o"

    # Disable TX and RX csum offloading, as veth does not support it. Otherwise,
    # the forwarded packets by the LB to the worker node will have invalid csums.
    sudo ethtool -K "${ifc}" rx off tx off > /dev/null
  done
fi

docker network connect "${default_network}" "${reg_name}" || true

for node in $(kind get nodes); do
  kubectl annotate node "${node}" "kind.x-k8s.io/registry=localhost:${reg_port}";
done

# Replace "forward . /etc/resolv.conf" in the coredns cm with "forward . 8.8.8.8".
# This is required because in case of BPF Host Routing we bypass iptables thus
# breaking DNS. See https://github.com/cilium/cilium/issues/23330
NewCoreFile=$(kubectl get cm -n kube-system coredns -o jsonpath='{.data.Corefile}' | sed 's,forward . /etc/resolv.conf,forward . 8.8.8.8,' | sed -z 's/\n/\\n/g')
kubectl patch configmap/coredns -n kube-system --type merge -p '{"data":{"Corefile": "'"$NewCoreFile"'"}}'

set +e
kubectl taint nodes --all node-role.kubernetes.io/master-
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
set -e

echo
echo "Images are pushed into the kind registry like so:"
echo "  export DOCKER_REGISTRY=localhost:5000"
echo "  make dev-docker-image"
