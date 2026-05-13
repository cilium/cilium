#!/usr/bin/env bash
#
# Bring up a 4-node kind cluster running Cilium built from the current
# working tree, configured for direct routing, kube-proxy replacement,
# netkit pod devices, SNAT load-balancing, and DSR-IPIP dispatch.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CILIUM_ROOT="$(realpath "${SCRIPT_DIR}/../..")"
CLUSTER_NAME="${CLUSTER_NAME:-kind}"

# 1 control-plane + 3 workers = 4 nodes, kube-proxy disabled, IPv4 only.
"${SCRIPT_DIR}/kind.sh" 1 3 "${CLUSTER_NAME}" "" none ipv4

# Build cilium-agent and cilium-operator images from the working tree
# and load them into the kind nodes.
make -C "${CILIUM_ROOT}" kind-image

EXTRA_VALUES="$(mktemp --suffix=.yaml)"
trap 'rm -f "${EXTRA_VALUES}"' EXIT

cat > "${EXTRA_VALUES}" <<'EOF'
routingMode: native
autoDirectNodeRoutes: true
ipv4NativeRoutingCIDR: 10.244.0.0/16
kubeProxyReplacement: "true"
bpf:
  datapathMode: netkit
  lbModeAnnotation: true
  masquerade: true
loadBalancer:
  mode: snat
  dsrDispatch: ipip
l2announcements:
  enabled: true
k8sClientRateLimit:
  qps: 10
  burst: 20
EOF

cilium install \
  --chart-directory="${CILIUM_ROOT}/install/kubernetes/cilium" \
  --helm-values="${CILIUM_ROOT}/contrib/testing/kind-values.yaml" \
  --helm-values="${EXTRA_VALUES}" \
  --version=

cilium status --wait
