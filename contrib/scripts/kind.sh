#!/usr/bin/env bash

# Source: https://kind.sigs.k8s.io/docs/user/local-registry/

set -euo pipefail

default_controlplanes=1
default_workers=1
default_cluster_name=""
default_image=""
default_kubeproxy_mode="iptables"
default_ipfamily="dual"
default_pod_subnet=""
default_service_subnet=""
default_agent_port_prefix="234"
default_operator_port_prefix="235"

PROG=${0}
controlplanes="${1:-${CONTROLPLANES:=${default_controlplanes}}}"
workers="${2:-${WORKERS:=${default_workers}}}"
cluster_name="${3:-${CLUSTER_NAME:=${default_cluster_name}}}"
# IMAGE controls the K8s version as well (e.g. kindest/node:v1.11.10)
image="${4:-${IMAGE:=${default_image}}}"
kubeproxy_mode="${5:-${KUBEPROXY_MODE:=${default_kubeproxy_mode}}}"
ipfamily="${6:-${IPFAMILY:=${default_ipfamily}}}"
pod_subnet="${PODSUBNET:=${default_pod_subnet}}"
service_subnet="${SERVICESUBNET:=${default_service_subnet}}"
agent_port_prefix="${AGENTPORTPREFIX:=${default_agent_port_prefix}}"
operator_port_prefix="${OPERATORPORTPREFIX:=${default_operator_port_prefix}}"
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
    local agentDebugPort="$agent_port_prefix$1$2"
    local operatorDebugPort="$operator_port_prefix$1$2"
    local max="$3"

    echo "  extraMounts:"
    echo "  - hostPath: $CILIUM_ROOT"
    echo "    containerPath: /home/vagrant/go/src/github.com/cilium/cilium"
    if [[ "${max}" -lt 10 ]]; then
        echo "  extraPortMappings:"
        echo "  - containerPort: 2345"
        echo "    hostPort: $agentDebugPort"
        echo "    listenAddress: \"127.0.0.1\""
        echo "    protocol: TCP"
        echo "  - containerPort: 2346"
        echo "    hostPort: $operatorDebugPort"
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
  ${pod_subnet:+"podSubnet: "$pod_subnet}
  ${service_subnet:+"serviceSubnet: "$service_subnet}
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:${reg_port}"]
EOF

docker network connect "kind" "${reg_name}" || true

for node in $(kubectl get nodes --no-headers -o custom-columns=:.metadata.name); do
  kubectl annotate node "${node}" "kind.x-k8s.io/registry=localhost:${reg_port}";
done

set +e
kubectl taint nodes --all node-role.kubernetes.io/master-
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
set -e

echo
echo "Kind is up! Time to install cilium:"
echo "  make kind-image"
echo "  make kind-install-cilium"
