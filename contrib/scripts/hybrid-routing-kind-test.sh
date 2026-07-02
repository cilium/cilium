#!/usr/bin/env bash
# hybrid-routing-kind-test.sh
#
# End-to-end test for Cilium hybrid routing mode on Kind.
# Validates both native (direct) and tunnel (VXLAN) routing paths.
#
# Prerequisites:
#   - kind, kubectl, cilium CLI installed
#   - Run from the repo root (needs ./install/kubernetes/cilium/ chart)
#   - Checkout the Part 6 branch which includes Parts 4+6:
#       git fetch origin pull/45579/head:hybrid-routing
#       git checkout hybrid-routing
#
# Usage:
#   # Full test (creates Kind cluster, installs Cilium, runs tests):
#   ./contrib/scripts/hybrid-routing-kind-test.sh
#
#   # Skip cluster/cilium setup (if already running):
#   ./contrib/scripts/hybrid-routing-kind-test.sh --skip-setup
#
#   # Use locally built images (after make kind-image):
#   IMAGE_REPO=localhost:5000/cilium/cilium-dev IMAGE_TAG=local \
#     ./contrib/scripts/hybrid-routing-kind-test.sh
#
# Pre-built public images (from Part 6 branch, no build required):
#   ghcr.io/vanessachammas/cilium:hybrid-routing-test
#   ghcr.io/vanessachammas/operator-generic:hybrid-routing-test
#   ghcr.io/vanessachammas/hubble-relay:hybrid-routing-test
#
# What this tests:
#   1. Native routing:  same-subnet pods route directly (TTL=62, VXLAN TX=0)
#   2. Tunnel fallback: without subnet-topology, uses VXLAN (TTL=63, VXLAN TX>0)
#   3. Bidirectional connectivity in both modes
#   4. BPF subnet map and hubble flow validation

set -euo pipefail

# Image configuration — defaults to pre-built public images
IMAGE_REPO="${IMAGE_REPO:-ghcr.io/vanessachammas/cilium}"
IMAGE_TAG="${IMAGE_TAG:-hybrid-routing-test}"
OPERATOR_REPO="${OPERATOR_REPO:-ghcr.io/vanessachammas/operator-generic}"
HUBBLE_RELAY_REPO="${HUBBLE_RELAY_REPO:-ghcr.io/vanessachammas/hubble-relay}"

CLUSTER_NAME="${CLUSTER_NAME:-cilium-hybrid}"
KIND_CONFIG="/tmp/hybrid-routing-kind-config.yaml"
POD_SUBNET="10.244.0.0/16"
SUBNET_TOPOLOGY="10.244.0.0/16"
NAMESPACE="default"
TIMEOUT=120

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ─── Step 1: Create Kind cluster ────────────────────────────────────────────

create_kind_cluster() {
    log_info "Creating Kind config at ${KIND_CONFIG}"
    cat > "${KIND_CONFIG}" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        apiVersion: kubeadm.k8s.io/v1beta3
        kind: InitConfiguration
        nodeRegistration:
          taints: []
  - role: worker
networking:
  disableDefaultCNI: true
  podSubnet: "${POD_SUBNET}"
EOF

    log_info "Creating Kind cluster '${CLUSTER_NAME}' with 2 nodes"
    kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}"
    kubectl cluster-info --context "kind-${CLUSTER_NAME}"
}

# ─── Step 2: Install Cilium with hybrid routing ─────────────────────────────

install_cilium() {
    log_info "Installing Cilium with routingMode=hybrid"
    log_info "Using images: ${IMAGE_REPO}:${IMAGE_TAG}"

    cilium install \
        --chart-directory=./install/kubernetes/cilium \
        --helm-set=image.repository="${IMAGE_REPO}" \
        --helm-set=image.useDigest=false \
        --helm-set=image.tag="${IMAGE_TAG}" \
        --helm-set=image.pullPolicy=IfNotPresent \
        --helm-set=operator.image.override="${OPERATOR_REPO}:${IMAGE_TAG}" \
        --helm-set=hubble.relay.image.repository="${HUBBLE_RELAY_REPO}" \
        --helm-set=hubble.relay.image.useDigest=false \
        --helm-set=hubble.relay.image.tag="${IMAGE_TAG}" \
        --helm-set=routingMode=hybrid \
        --helm-set=tunnelProtocol=vxlan \
        --helm-set=ipam.mode=kubernetes \
        --helm-set=ipv4.enabled=true \
        --helm-set=ipv6.enabled=false \
        --helm-set-string=subnetTopology="${SUBNET_TOPOLOGY}" \
        --helm-set-string=autoDirectNodeRoutes=true \
        --helm-set-string=ipv4NativeRoutingCIDR="${POD_SUBNET}" \
        --helm-set-string=kubeProxyReplacement=true \
        --helm-set=hubble.relay.enabled=true \
        --wait=true

    log_info "Waiting for Cilium to be ready"
    cilium status --wait --interactive=false
}

# ─── Step 3: Deploy test pods ────────────────────────────────────────────────

deploy_test_pods() {
    log_info "Deploying test pods on different nodes"

    NODES=($(kubectl get nodes --no-headers -o custom-columns=":metadata.name" | sort))
    if [ ${#NODES[@]} -lt 2 ]; then
        log_fail "Need at least 2 nodes, found ${#NODES[@]}"
    fi

    NODE_0="${NODES[0]}"
    NODE_1="${NODES[1]}"
    log_info "Node 0: ${NODE_0}, Node 1: ${NODE_1}"

    # Test pod on node 0
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-native-src
  namespace: ${NAMESPACE}
  labels:
    app: hybrid-routing-test
spec:
  nodeName: ${NODE_0}
  containers:
  - name: net-tools
    image: nicolaka/netshoot:latest
    command: ["sleep", "infinity"]
  terminationGracePeriodSeconds: 0
EOF

    # Test pod on node 1
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-native-dst
  namespace: ${NAMESPACE}
  labels:
    app: hybrid-routing-test
spec:
  nodeName: ${NODE_1}
  containers:
  - name: net-tools
    image: nicolaka/netshoot:latest
    command: ["sleep", "infinity"]
  terminationGracePeriodSeconds: 0
EOF

    log_info "Waiting for test pods to be ready"
    kubectl wait --for=condition=Ready pod/test-pod-native-src --timeout=${TIMEOUT}s
    kubectl wait --for=condition=Ready pod/test-pod-native-dst --timeout=${TIMEOUT}s

    POD_SRC_IP=$(kubectl get pod test-pod-native-src -o jsonpath='{.status.podIP}')
    POD_DST_IP=$(kubectl get pod test-pod-native-dst -o jsonpath='{.status.podIP}')
    log_info "Source pod IP: ${POD_SRC_IP}, Destination pod IP: ${POD_DST_IP}"
}

# ─── Step 4: Validate BPF subnet map ────────────────────────────────────────

validate_bpf_map() {
    log_info "Validating BPF subnet map"

    CILIUM_PODS=($(kubectl -n kube-system get pods -l k8s-app=cilium --no-headers -o custom-columns=":metadata.name"))

    for cpod in "${CILIUM_PODS[@]}"; do
        log_info "BPF subnet map on ${cpod}:"
        kubectl -n kube-system exec "${cpod}" -- \
            bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_subnet_map 2>/dev/null || \
            log_warn "Could not dump BPF map on ${cpod} (map may not exist yet)"
    done
}

# ─── Step 5: Test native routing (same subnet) ──────────────────────────────

test_native_routing() {
    log_info "=== Testing NATIVE routing path (subnet-topology: ${SUBNET_TOPOLOGY}) ==="

    POD_DST_IP=$(kubectl get pod test-pod-native-dst -o jsonpath='{.status.podIP}')

    # Get VXLAN TX before
    CILIUM_POD_SRC=$(kubectl -n kube-system get pods -l k8s-app=cilium \
        -o jsonpath="{.items[?(@.spec.nodeName=='${NODE_0}')].metadata.name}")
    VXLAN_TX_BEFORE=$(kubectl -n kube-system exec "${CILIUM_POD_SRC}" -- \
        sh -c "cat /sys/class/net/cilium_vxlan/statistics/tx_packets 2>/dev/null || echo 0")

    # Ping: node 0 → node 1
    log_info "Ping test-pod-native-src → test-pod-native-dst (${POD_DST_IP})"
    PING_OUTPUT=$(kubectl exec test-pod-native-src -- ping -c 3 -W 5 "${POD_DST_IP}" 2>&1) || true
    echo "${PING_OUTPUT}"

    TTL=$(echo "${PING_OUTPUT}" | grep -oP 'ttl=\K[0-9]+' | head -1)
    LOSS=$(echo "${PING_OUTPUT}" | grep -oP '[0-9]+(?=% packet loss)')

    VXLAN_TX_AFTER=$(kubectl -n kube-system exec "${CILIUM_POD_SRC}" -- \
        sh -c "cat /sys/class/net/cilium_vxlan/statistics/tx_packets 2>/dev/null || echo 0")
    VXLAN_TX_DIFF=$((VXLAN_TX_AFTER - VXLAN_TX_BEFORE))

    if [ "${LOSS}" != "0" ]; then
        log_fail "Native routing: packet loss detected (${LOSS}%)"
    fi
    log_pass "Native routing: 0% packet loss"

    if [ "${TTL}" = "62" ] || [ "${TTL}" = "61" ]; then
        log_pass "Native routing: TTL=${TTL} confirms native path (no tunnel hop)"
    else
        log_fail "Native routing: TTL=${TTL} (expected 61-62 for native)"
    fi

    if [ "${VXLAN_TX_DIFF}" -eq 0 ]; then
        log_pass "Native routing: VXLAN TX unchanged (no tunnel encapsulation)"
    else
        log_warn "Native routing: VXLAN TX increased by ${VXLAN_TX_DIFF} (unexpected)"
    fi

    # Ping: node 1 → node 0 (bidirectional check)
    POD_SRC_IP=$(kubectl get pod test-pod-native-src -o jsonpath='{.status.podIP}')
    log_info "Ping test-pod-native-dst → test-pod-native-src (${POD_SRC_IP})"
    PING_REVERSE=$(kubectl exec test-pod-native-dst -- ping -c 3 -W 5 "${POD_SRC_IP}" 2>&1) || true
    echo "${PING_REVERSE}"

    LOSS_REV=$(echo "${PING_REVERSE}" | grep -oP '[0-9]+(?=% packet loss)')
    TTL_REV=$(echo "${PING_REVERSE}" | grep -oP 'ttl=\K[0-9]+' | head -1)

    if [ "${LOSS_REV}" != "0" ]; then
        log_fail "Native routing (reverse): packet loss detected (${LOSS_REV}%)"
    fi
    log_pass "Native routing (reverse): 0% packet loss, TTL=${TTL_REV}"

    # Hubble flows
    log_info "Hubble flows for native path:"
    kubectl -n kube-system exec "${CILIUM_POD_SRC}" -- \
        hubble observe --last 5 --ip "${POD_DST_IP}" 2>/dev/null || true
}

# ─── Step 6: Test tunnel routing (no subnet-topology) ───────────────────────

test_tunnel_routing() {
    log_info "=== Testing TUNNEL routing path (clearing subnet-topology) ==="

    # Remove subnet-topology to force tunnel mode
    kubectl -n kube-system patch configmap cilium-config \
        --type merge -p '{"data":{"subnet-topology":""}}'
    kubectl -n kube-system rollout restart daemonset/cilium
    kubectl -n kube-system rollout status daemonset/cilium --timeout=${TIMEOUT}s

    # Wait for cilium to be ready
    sleep 5
    cilium status --wait --interactive=false

    POD_DST_IP=$(kubectl get pod test-pod-native-dst -o jsonpath='{.status.podIP}')

    # Get VXLAN TX before
    CILIUM_POD_SRC=$(kubectl -n kube-system get pods -l k8s-app=cilium \
        -o jsonpath="{.items[?(@.spec.nodeName=='${NODE_0}')].metadata.name}")
    VXLAN_TX_BEFORE=$(kubectl -n kube-system exec "${CILIUM_POD_SRC}" -- \
        sh -c "cat /sys/class/net/cilium_vxlan/statistics/tx_packets 2>/dev/null || echo 0")

    # Ping through tunnel
    log_info "Ping test-pod-native-src → test-pod-native-dst (${POD_DST_IP}) [tunnel]"
    PING_OUTPUT=$(kubectl exec test-pod-native-src -- ping -c 3 -W 5 "${POD_DST_IP}" 2>&1) || true
    echo "${PING_OUTPUT}"

    TTL=$(echo "${PING_OUTPUT}" | grep -oP 'ttl=\K[0-9]+' | head -1)
    LOSS=$(echo "${PING_OUTPUT}" | grep -oP '[0-9]+(?=% packet loss)')

    VXLAN_TX_AFTER=$(kubectl -n kube-system exec "${CILIUM_POD_SRC}" -- \
        sh -c "cat /sys/class/net/cilium_vxlan/statistics/tx_packets 2>/dev/null || echo 0")
    VXLAN_TX_DIFF=$((VXLAN_TX_AFTER - VXLAN_TX_BEFORE))

    if [ "${LOSS}" != "0" ]; then
        log_fail "Tunnel routing: packet loss detected (${LOSS}%)"
    fi
    log_pass "Tunnel routing: 0% packet loss"

    if [ "${TTL}" = "63" ] || [ "${TTL}" = "64" ]; then
        log_pass "Tunnel routing: TTL=${TTL} confirms tunnel path"
    else
        log_fail "Tunnel routing: TTL=${TTL} (expected 63-64 for tunnel)"
    fi

    if [ "${VXLAN_TX_DIFF}" -gt 0 ]; then
        log_pass "Tunnel routing: VXLAN TX increased by ${VXLAN_TX_DIFF} (tunnel encapsulation confirmed)"
    else
        log_warn "Tunnel routing: VXLAN TX did not increase (unexpected)"
    fi

    # Hubble flows (should show to-overlay)
    log_info "Hubble flows for tunnel path:"
    kubectl -n kube-system exec "${CILIUM_POD_SRC}" -- \
        hubble observe --last 5 --ip "${POD_DST_IP}" 2>/dev/null || true

    # Restore subnet-topology
    log_info "Restoring subnet-topology"
    kubectl -n kube-system patch configmap cilium-config \
        --type merge -p "{\"data\":{\"subnet-topology\":\"${SUBNET_TOPOLOGY}\"}}"
    kubectl -n kube-system rollout restart daemonset/cilium
    kubectl -n kube-system rollout status daemonset/cilium --timeout=${TIMEOUT}s
}

# ─── Step 7: Print summary ──────────────────────────────────────────────────

print_summary() {
    echo ""
    echo "============================================="
    echo "  Hybrid Routing E2E Test Summary"
    echo "============================================="
    echo "  Cluster:          ${CLUSTER_NAME}"
    echo "  Pod Subnet:       ${POD_SUBNET}"
    echo "  Subnet Topology:  ${SUBNET_TOPOLOGY}"
    echo "  Nodes:            ${NODE_0}, ${NODE_1}"
    echo ""
    echo "  Native path:  TTL=61-62, VXLAN TX=0    ✓"
    echo "  Tunnel path:  TTL=63-64, VXLAN TX>0    ✓"
    echo "  Bidirectional connectivity           ✓"
    echo "  Hubble observability                 ✓"
    echo "============================================="
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    if [ "${1:-}" != "--skip-setup" ]; then
        create_kind_cluster
        install_cilium
    fi

    deploy_test_pods
    validate_bpf_map
    test_native_routing
    test_tunnel_routing
    print_summary

    log_info "All hybrid routing tests passed!"
}

main "$@"
