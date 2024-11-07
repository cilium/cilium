#!/usr/bin/env bash

# Source: https://kind.sigs.k8s.io/docs/user/local-registry/

set -euo pipefail

usage() {
  echo "Usage: ${PROG} [--xdp] [--secondary-network] [--optimize-sysctl] [--external-dns ipv4-addr] [control-plane node count] [worker node count] [cluster-name] [node image] [kube-proxy mode] [ip-family] [apiserver-addr] [apiserver-port] [kubeconfig-path]"
}

default_controlplanes=1
default_workers=1
default_cluster_name="kind"
default_image=""
default_kubeproxy_mode="iptables"
if [ "$(uname 2>/dev/null)" == "Linux" ] && [ "$(</proc/sys/net/ipv6/conf/all/disable_ipv6)" == 1 ] ; then
  default_ipfamily="ipv4"
else
  default_ipfamily="dual"
fi
default_pod_subnet=""
default_service_subnet=""
default_agent_port_prefix="234"
default_operator_port_prefix="235"
default_network="kind-cilium"
default_apiserver_addr="127.0.0.1"
default_apiserver_port=0 # kind will randomly select
default_kubeconfig=""
default_external_dns="1.1.1.1"
secondary_network="${default_network}-secondary"

PROG=${0}

SED="${SED:-sed}"

xdp=false
secondary_network_flag=false
optimize_sysctl=false
external_dns="${EXTERNAL_DNS:=${default_external_dns}}"
while :; do
  case "${1:-}" in
    "--xdp")
      xdp=true
      shift;;
    "--secondary-network")
      secondary_network_flag=true
      shift;;
    "--optimize-sysctl")
      optimize_sysctl=true
      shift;;
    "--external-dns")
      if [[ $# -lt 2 || ! "$2" =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        usage
        exit 1
      fi
      external_dns="$2"
      shift 2;;
    "--help"|"-h")
      usage
      exit 0;;
    *)
      break;;
  esac
done
readonly xdp
readonly secondary_network_flag
readonly optimize_sysctl
readonly external_dns

controlplanes="${1:-${CONTROLPLANES:=${default_controlplanes}}}"
workers="${2:-${WORKERS:=${default_workers}}}"
cluster_name="${3:-${CLUSTER_NAME:=${default_cluster_name}}}"
# IMAGE controls the K8s version as well (e.g. kindest/node:v1.11.10)
image="${4:-${IMAGE:=${default_image}}}"
kubeproxy_mode="${5:-${KUBEPROXY_MODE:=${default_kubeproxy_mode}}}"
ipfamily="${6:-${IPFAMILY:=${default_ipfamily}}}"
apiserver_addr="${7:-${APISERVER_ADDR:=${default_apiserver_addr}}}"
apiserver_port="${8:-${APISERVER_PORT:=${default_apiserver_port}}}"
kubeconfig="${9:-${KUBECONFIG:=${default_kubeconfig}}}"
pod_subnet="${PODSUBNET:=${default_pod_subnet}}"
service_subnet="${SERVICESUBNET:=${default_service_subnet}}"
agent_port_prefix="${AGENTPORTPREFIX:=${default_agent_port_prefix}}"
operator_port_prefix="${OPERATORPORTPREFIX:=${default_operator_port_prefix}}"

bridge_dev="br-${default_network}"
bridge_dev_secondary="${bridge_dev}2"
v4_prefix_secondary="192.168.0.0/16"
v4_range_secondary="192.168.0.0/24"
v6_prefix="fc00:c111::/64"
v6_prefix_secondary="fc00:c112::/64"
CILIUM_ROOT="$(git rev-parse --show-toplevel)"

have_kind() {
    [[ -n "$(command -v kind)" ]]
}

if ! have_kind; then
    echo "Please install kind first:"
    echo "  https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    exit 1
fi

have_kubectl() {
    [[ -n "$(command -v kubectl)" ]]
}

if ! have_kubectl; then
    echo "Please install kubectl first:"
    echo "  https://kubernetes.io/docs/tasks/tools/#kubectl"
    exit 1
fi

if [ ${#} -gt 9 ]; then
  usage
  exit 1
fi

kind_cmd="kind create cluster"

kind_cmd+=" --name ${cluster_name}"

if [[ -n "${image}" ]]; then
  kind_cmd+=" --image ${image}"
fi
if [[ -n "${kubeconfig}" ]]; then
  dir=$(cd $(dirname ${kubeconfig} ); pwd)
  file_name=$(basename ${kubeconfig})
  mkdir -p ${dir} &>/dev/null
  kubeconfig=${dir}/${file_name}
  kind_cmd+=" --kubeconfig ${kubeconfig}"
  export KUBECONFIG=${kubeconfig}
fi

node_config() {
    local agentDebugPort="$agent_port_prefix$1$2"
    local operatorDebugPort="$operator_port_prefix$1$2"
    local max="$3"

    echo "  extraMounts:"
    echo "  - hostPath: $CILIUM_ROOT"
    echo "    containerPath: /home/vagrant/go/src/github.com/cilium/cilium"
    # Kubelet drop-in that replaces the nameserver configured by the container engine
    # with dnsmasq defaulting to $external_dns, but deferring local lookups to docker
    # so that kubelets can resolve nodes by name.
    # This is required for two reasons:
    # (a) in case of BPF Host Routing we bypass iptables thus breaking DNS.
    #     See https://github.com/cilium/cilium/issues/23330
    # (b) In case host has L7 DNS policy dockerd's iptables rule acts before
    #     we redirect the DNS request to proxy port, breaking DNS proxy.
    echo "  - hostPath: $CILIUM_ROOT/contrib/scripts/kind-kubelet.conf"
    echo "    containerPath: /etc/systemd/system/kubelet.service.d/12-cilium.conf"
    echo "    readOnly: true"
    # Mount a safe dummy file at a safe container path to pass in external DNS address
    # without having to write to our source filesystem (i.e. where kind.sh is running)
    echo "  - hostPath: /dev/null"
    echo "    containerPath: /etc/kind-external-dns-$external_dns.conf"
    echo "    readOnly: true"
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

echo "${kind_cmd}"

kind --version

# create a custom network so we can control the name of the bridge device.
# Inspired by https://github.com/kubernetes-sigs/kind/blob/6b58c9dfcbdb1b3a0d48754d043d59ca7073589b/pkg/cluster/internal/providers/docker/network.go#L149-L161
# This operation is skipped if the network is already present (most notably in case of "make kind-clustermesh")
if ! docker network inspect "${default_network}" >/dev/null 2>&1; then
  docker network create -d=bridge \
    -o "com.docker.network.bridge.enable_ip_masquerade=true" \
    -o "com.docker.network.bridge.name=${bridge_dev}" \
    --ipv6 --subnet "${v6_prefix}" \
    "${default_network}"
fi

if [ "${optimize_sysctl}" = true ]; then
    if [ "$(uname 2>/dev/null)" == "Linux" ] ; then
        # fix a typical issue to make sure the kind cluster succeed to run even if the resource is short
        # issue: https://github.com/kubernetes-sigs/kind/issues/2744
        # issue: https://github.com/kubernetes-sigs/kind/issues/2586
        sysctl -w fs.inotify.max_user_watches=1048576
        sysctl -w fs.inotify.max_user_instances=512
    else
        echo "ERROR: no support for optimizing sysctl on a non-linux host"
        exit 1
    fi
fi

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
  ${pod_subnet:+"podSubnet: "$pod_subnet}
  ${service_subnet:+"serviceSubnet: "$service_subnet}
  apiServerAddress: ${apiserver_addr}
  apiServerPort: ${apiserver_port}

kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    metadata:
      name: config
    apiServer:
      extraArgs:
        "v": "3"
EOF

if [ "${secondary_network_flag}" = true ]; then
  if ! docker network inspect "${secondary_network}" >/dev/null 2>&1; then
    docker network create -d=bridge \
      -o "com.docker.network.bridge.enable_ip_masquerade=false" \
      -o "com.docker.network.bridge.name=${bridge_dev_secondary}" \
      --subnet "${v4_prefix_secondary}" \
      --ip-range "${v4_range_secondary}" \
      --ipv6 --subnet "${v6_prefix_secondary}" \
      "${secondary_network}"
  fi

  kind get nodes --name kind | xargs -L1 docker network connect ${secondary_network}
fi

if [ "${xdp}" = true ]; then
  if ! [ -f "${CILIUM_ROOT}/test/l4lb/bpf_xdp_veth_host.o" ]; then
    pushd "${CILIUM_ROOT}/test/l4lb/" > /dev/null
    clang -O2 -Wall --target=bpf -c bpf_xdp_veth_host.c -o bpf_xdp_veth_host.o
    popd > /dev/null
  fi

  for ifc in /sys/class/net/"${bridge_dev}"*/brif/*; do
    ifc=$(echo $ifc | "${SED}" "s,/sys/class/net/${bridge_dev}.*/brif/,,")

    # Attach a dummy XDP prog to the host side of the veth so that XDP_TX in the
    # pod side works.
    sudo ip link set dev "${ifc}" xdp obj "${CILIUM_ROOT}/test/l4lb/bpf_xdp_veth_host.o"

    # Disable TX and RX csum offloading, as veth does not support it. Otherwise,
    # the forwarded packets by the LB to the worker node will have invalid csums.
    sudo ethtool -K "${ifc}" rx off tx off > /dev/null
  done
fi

# 1) Replace "forward . /etc/resolv.conf" in the coredns cm with "forward . $external_dns".
# This is required because in case of BPF Host Routing we bypass iptables thus
# breaking DNS. See https://github.com/cilium/cilium/issues/23330
# 2) Enable the log plugin to log all DNS queries for debugging.
NewCoreFile=$(kubectl get cm -n kube-system coredns -o jsonpath='{.data.Corefile}' | "${SED}" "s,forward . /etc/resolv.conf,forward . $external_dns," | "${SED}" 's/loadbalance/loadbalance\n    log/' | awk ' { printf "%s\\n", $0 } ')
kubectl patch configmap/coredns -n kube-system --type merge -p '{"data":{"Corefile": "'"$NewCoreFile"'"}}'

set +e
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
kubectl taint nodes --all node-role.kubernetes.io/master-
set -e

# Set start of unprivileged port range to 1024
# Docker defaults to 0
# https://github.com/moby/moby/pull/41030
kind get nodes --name $cluster_name | xargs -I container_name docker exec container_name sysctl -w net.ipv4.ip_unprivileged_port_start=1024

echo
if [[ -n "${kubeconfig}" ]]; then
  echo "export KUBECONFIG=${kubeconfig}"
fi
echo "Kind is up! Time to install cilium:"
echo "  make kind-image"
echo "  make kind-install-cilium"
echo ""
echo "On Linux, the below can be used for faster feedback:"
echo "  make kind-image-fast"
echo "  make kind-install-cilium-fast"
