#!/usr/bin/env bash

# Source: https://kind.sigs.k8s.io/docs/user/local-registry/

set -euo pipefail

default_controlplanes=1
default_workers=1
default_cluster_name=""
default_image=""
default_kubeproxy_mode="iptables"
default_ipfamily="ipv4"

PROG=${0}
controlplanes="${1:-${CONTROLPLANES:=${default_controlplanes}}}"
workers="${2:-${WORKERS:=${default_workers}}}"
cluster_name="${3:-${CLUSTER_NAME:=${default_cluster_name}}}"
# IMAGE controls the K8s version as well (e.g. kindest/node:v1.11.10)
image="${4:-${IMAGE:=${default_image}}}"
kubeproxy_mode="${5:-${KUBEPROXY_MODE:=${default_kubeproxy_mode}}}"
ipfamily="${6:-${IPFAMILY:=${default_ipfamily}}}"
CILIUM_ROOT="$(git rev-parse --show-toplevel)"

usage() {
  echo "Usage: ${PROG} [control-plane node count] [worker node count] [cluster-name] [node image] [kube-proxy mode] [ip-family]"
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

control_planes() {
  for _ in $(seq 1 "${controlplanes}"); do
    echo "- role: control-plane"
    echo "  extraMounts:"
    echo "  - hostPath: $CILIUM_ROOT"
    echo "    containerPath: /home/vagrant/go/src/github.com/cilium/cilium"
  done
}

workers() {
  for _ in $(seq 1 "${workers}"); do
    echo "- role: worker"
    echo "  extraMounts:"
    echo "  - hostPath: $CILIUM_ROOT"
    echo "    containerPath: /home/vagrant/go/src/github.com/cilium/cilium"
  done
}

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

docker network connect "kind" "${reg_name}" || true

for node in $(kind get nodes); do
  kubectl annotate node "${node}" "kind.x-k8s.io/registry=localhost:${reg_port}";
done

set +e
kubectl taint nodes --all node-role.kubernetes.io/master-
set -e

echo
echo "Images are pushed into the kind registry like so:"
echo "  export DOCKER_REGISTRY=localhost:5000"
echo "  make dev-docker-image"
