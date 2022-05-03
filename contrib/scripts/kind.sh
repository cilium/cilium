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
CONTROLPLANES="${1:-${default_controlplanes}}"
WORKERS="${2:-${default_workers}}"
CLUSTER_NAME="${3:-${default_cluster_name}}"
# IMAGE controls the K8s version as well (e.g. kindest/node:v1.11.10)
IMAGE="${4:-${default_image}}"
KUBEPROXY_MODE="${5:-${default_kubeproxy_mode}}"
IPFAMILY="${6:-${default_ipfamily}}"
CILIUM_ROOT="$(realpath $(dirname $(readlink -ne $BASH_SOURCE))/../..)"

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

if [[ "${CONTROLPLANES}" == "-h" || "${CONTROLPLANES}" == "--help" ]]; then
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

if [[ -n "${CLUSTER_NAME}" ]]; then
  kind_cmd+=" --name ${CLUSTER_NAME}"
fi
if [[ -n "${IMAGE}" ]]; then
  kind_cmd+=" --image ${IMAGE}"
fi

control_planes() {
  for _ in $(seq 1 "${CONTROLPLANES}"); do
    echo "- role: control-plane"
    echo "  extraMounts:"
    echo "  - hostPath: $CILIUM_ROOT"
    echo "    containerPath: /home/vagrant/go/src/github.com/cilium/cilium"
  done
}

workers() {
  for _ in $(seq 1 "${WORKERS}"); do
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
  kubeProxyMode: ${KUBEPROXY_MODE}
  ipFamily: ${IPFAMILY}
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
