#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
#
# VTEP CRD integration test script.
# Validates BPF map population, nodeSelector filtering, VXLAN connectivity,
# dynamic CRD updates, and CRD deletion.
#
# Prerequisites: Kind cluster with Cilium (vtep.enabled=true), VTEP responder
# containers running, CiliumVTEPConfig CRDs applied, and probe pods deployed.
#
# This script is shared between CI (conformance-vtep.yaml) and local testing.
#
# BPF map JSON format (from cilium-dbg bpf vtep list -o json):
#   {"10.1.5.0/24": ["vtepmac=AA:BB:CC:DD:EE:FF tunnelendpoint=172.20.1.10"]}
# Keys are CIDR strings (e.g. "10.1.5.0/24") matching the LPM trie key format.

set -euo pipefail

# Tunnel endpoint IPs — must match the values in zone-a-vtep.yaml / zone-b-vtep.yaml.
# Override via env vars when responders land on non-default IPs (e.g. local testing).
VTEP_A_IP="${VTEP_A_IP:-172.20.1.10}"
VTEP_B_IP="${VTEP_B_IP:-172.20.1.11}"

# Docker network name that both the Kind nodes and VTEP responders share.
# Used when programming permanent FDB / ARP entries on the responders.
VTEP_NETWORK="${VTEP_NETWORK:-kind}"

PASS=0
FAIL=0

pass() {
  PASS=$((PASS + 1))
  echo "  PASS: $1"
}

fail() {
  FAIL=$((FAIL + 1))
  echo "  FAIL: $1" >&2
}

phase() {
  echo ""
  echo "=== Phase $1: $2 ==="
}

# Helper: get cilium pod name for a given node
cilium_pod_on() {
  local node="$1"
  kubectl -n kube-system get pod -l k8s-app=cilium \
    --field-selector "spec.nodeName=$node" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# Helper: get VTEP BPF map entries as JSON from a specific node.
# Output format: {"<masked_ip>": ["vtepmac=<mac> tunnelendpoint=<ip>"], ...}
# Returns "{}" on error (empty object, not empty array).
vtep_bpf_list() {
  local node="$1"
  local pod
  pod=$(cilium_pod_on "$node")
  kubectl -n kube-system exec "$pod" -c cilium-agent -- \
    cilium-dbg bpf vtep list -o json 2>/dev/null || echo "{}"
}

# Helper: check if BPF map output contains a specific tunnel endpoint.
# Args: $1=json_data, $2=tunnel_endpoint_ip
bpf_has_tunnel_endpoint() {
  local json="$1"
  local endpoint="$2"
  echo "$json" | jq -e "to_entries[] | select(.value[] | contains(\"tunnelendpoint=$endpoint\"))" > /dev/null 2>&1
}

# Helper: count entries in BPF map JSON (object keys, not array length).
bpf_entry_count() {
  local json="$1"
  echo "$json" | jq 'keys | length'
}

# Helper: program permanent FDB and ARP entries on a VTEP responder so that
# ICMP replies have a reliable forwarding path back to the originating pod.
#
# Without permanent entries the kernel relies on MAC learning (TTL ~300s) and
# dynamic ARP, both of which can expire before or during a test run.
#
# Args: $1=responder_container, $2=probe_pod, $3=kind_node
seed_responder_tables() {
  local RESPONDER="$1"
  local POD="$2"
  local NODE="$3"

  local POD_IP POD_MAC NODE_IP
  POD_IP=$(kubectl get pod "$POD" -o jsonpath='{.status.podIP}' 2>/dev/null || true)
  POD_MAC=$(kubectl exec "$POD" -- cat /sys/class/net/eth0/address 2>/dev/null || true)
  NODE_IP=$(docker inspect "$NODE" \
    -f "{{(index .NetworkSettings.Networks \"$VTEP_NETWORK\").IPAddress}}" 2>/dev/null || true)

  if [ -z "$POD_IP" ] || [ -z "$POD_MAC" ] || [ -z "$NODE_IP" ]; then
    echo "  Warning: cannot seed $RESPONDER (pod_ip=$POD_IP pod_mac=$POD_MAC node_ip=$NODE_IP)"
    return
  fi

  echo "  Seeding $RESPONDER: $POD $POD_IP ($POD_MAC) via $NODE ($NODE_IP)"

  # Permanent FDB: inner dst MAC → outer node IP (so VXLAN replies reach the right node)
  docker exec "$RESPONDER" bridge fdb replace "$POD_MAC" dev vxlan0 dst "$NODE_IP" permanent 2>/dev/null || true
  # Permanent ARP neighbor: pod IP → pod MAC (so kernel can build Ethernet frame for the reply)
  docker exec "$RESPONDER" ip neigh replace "$POD_IP" lladdr "$POD_MAC" dev vxlan0 nud permanent 2>/dev/null || true
}

# ── Phase 0: Wait for BPF map reconciliation ─────────────────

phase 0 "Waiting for BPF map reconciliation"

echo "  Waiting for VTEP BPF entries to appear on worker nodes..."
W1_COUNT=0
W2_COUNT=0
for i in $(seq 1 30); do
  VTEP_WORKER=$(vtep_bpf_list "kind-worker")
  VTEP_WORKER2=$(vtep_bpf_list "kind-worker2")
  W1_COUNT=$(bpf_entry_count "$VTEP_WORKER")
  W2_COUNT=$(bpf_entry_count "$VTEP_WORKER2")
  if [ "$W1_COUNT" -gt 0 ] && [ "$W2_COUNT" -gt 0 ]; then
    echo "  BPF maps populated (worker=$W1_COUNT, worker2=$W2_COUNT entries)"
    break
  fi
  sleep 2
done

if [ "$W1_COUNT" -eq 0 ] || [ "$W2_COUNT" -eq 0 ]; then
  fail "Timed out waiting for BPF entries (worker=$W1_COUNT, worker2=$W2_COUNT)"
  echo "FATAL: Cannot continue without BPF entries"
  exit 1
fi

# ── Phase 1: BPF Map Verification ──────────────────────────

phase 1 "BPF Map Verification"

echo "  Checking worker (zone-a) BPF map..."
VTEP_WORKER=$(vtep_bpf_list "kind-worker")
if bpf_has_tunnel_endpoint "$VTEP_WORKER" "$VTEP_A_IP"; then
  pass "kind-worker has tunnelEndpoint $VTEP_A_IP"
else
  fail "kind-worker missing tunnelEndpoint $VTEP_A_IP. Got: $VTEP_WORKER"
fi

echo "  Checking worker2 (zone-b) BPF map..."
VTEP_WORKER2=$(vtep_bpf_list "kind-worker2")
if bpf_has_tunnel_endpoint "$VTEP_WORKER2" "$VTEP_B_IP"; then
  pass "kind-worker2 has tunnelEndpoint $VTEP_B_IP"
else
  fail "kind-worker2 missing tunnelEndpoint $VTEP_B_IP. Got: $VTEP_WORKER2"
fi

# ── Phase 2: NodeSelector — Control Plane Has No Entries ────

phase 2 "NodeSelector Filtering"

echo "  Checking control-plane BPF map (should be empty)..."
VTEP_CP=$(vtep_bpf_list "kind-control-plane")
CP_COUNT=$(bpf_entry_count "$VTEP_CP")
if [ "$CP_COUNT" -eq 0 ]; then
  pass "control-plane has 0 VTEP entries (nodeSelector filtering works)"
else
  fail "control-plane has $CP_COUNT VTEP entries, expected 0. Got: $VTEP_CP"
fi

# ── Phase 3: VXLAN Connectivity ─────────────────────────────

phase 3 "VXLAN Connectivity"

echo "  Waiting for probe pods to be ready..."
kubectl wait --for=condition=Ready pod/probe-zone-a pod/probe-zone-b --timeout=120s

# Seed permanent FDB and ARP entries so ICMP replies are forwarded reliably.
# Dynamically learned entries expire after ~300s; permanent entries never do.
echo "  Seeding permanent FDB/ARP entries on VTEP responders..."
seed_responder_tables "vtep-responder-a" "probe-zone-a" "kind-worker"
seed_responder_tables "vtep-responder-b" "probe-zone-b" "kind-worker2"

rx_bytes() { docker exec "$1" cat /sys/class/net/vxlan0/statistics/rx_bytes 2>/dev/null || echo "0"; }

# Snapshot RX counters before each ping to verify per-zone traffic isolation:
# zone-a traffic must reach vtep-responder-a only, zone-b must reach vtep-responder-b only.

echo "  Pinging 10.1.5.1 from zone-a pod..."
PRE_A_RX_A=$(rx_bytes vtep-responder-a)
PRE_A_RX_B=$(rx_bytes vtep-responder-b)
if kubectl exec probe-zone-a -- ping -c 5 -W 5 10.1.5.1; then
  pass "zone-a pod can reach 10.1.5.1 via VXLAN tunnel"
else
  fail "zone-a pod cannot reach 10.1.5.1"
fi
POST_A_RX_A=$(rx_bytes vtep-responder-a)
POST_A_RX_B=$(rx_bytes vtep-responder-b)

if [ "$POST_A_RX_A" -gt "$PRE_A_RX_A" ]; then
  pass "zone-a ping reached vtep-responder-a (RX $PRE_A_RX_A → $POST_A_RX_A bytes)"
else
  fail "vtep-responder-a saw no new traffic from zone-a ping"
fi
if [ "$POST_A_RX_B" -eq "$PRE_A_RX_B" ]; then
  pass "zone-a ping did NOT reach vtep-responder-b (traffic isolation)"
else
  fail "vtep-responder-b received zone-a traffic — nodeSelector isolation broken (RX $PRE_A_RX_B → $POST_A_RX_B bytes)"
fi

echo "  Pinging 10.1.5.1 from zone-b pod..."
PRE_B_RX_A=$(rx_bytes vtep-responder-a)
PRE_B_RX_B=$(rx_bytes vtep-responder-b)
if kubectl exec probe-zone-b -- ping -c 5 -W 5 10.1.5.1; then
  pass "zone-b pod can reach 10.1.5.1 via VXLAN tunnel"
else
  fail "zone-b pod cannot reach 10.1.5.1"
fi
POST_B_RX_A=$(rx_bytes vtep-responder-a)
POST_B_RX_B=$(rx_bytes vtep-responder-b)

if [ "$POST_B_RX_B" -gt "$PRE_B_RX_B" ]; then
  pass "zone-b ping reached vtep-responder-b (RX $PRE_B_RX_B → $POST_B_RX_B bytes)"
else
  fail "vtep-responder-b saw no new traffic from zone-b ping"
fi
if [ "$POST_B_RX_A" -eq "$PRE_B_RX_A" ]; then
  pass "zone-b ping did NOT reach vtep-responder-a (traffic isolation)"
else
  fail "vtep-responder-a received zone-b traffic — nodeSelector isolation broken (RX $PRE_B_RX_A → $POST_B_RX_A bytes)"
fi

# ── Phase 4: Dynamic Update — Change MAC ────────────────────

phase 4 "Dynamic CRD Update"

# Capture the real responder MAC before patching so we can restore it afterward.
# Connectivity tests require the correct MAC since the kernel VXLAN interface
# drops inner Ethernet frames whose destination MAC doesn't match its own MAC.
REAL_MAC_A=$(docker exec vtep-responder-a cat /sys/class/net/vxlan0/address 2>/dev/null || echo "")
if [ -z "$REAL_MAC_A" ]; then
  fail "Could not read real MAC from vtep-responder-a — skipping Phase 4"
else

echo "  Patching zone-a config with a sentinel MAC to verify BPF update..."
kubectl patch ciliumvtepconfig zone-a --type=merge -p "{
  \"spec\": {\"endpoints\": [{\"name\": \"router-a\", \"cidr\": \"10.1.5.0/24\",
    \"tunnelEndpoint\": \"$VTEP_A_IP\", \"mac\": \"AA:BB:CC:DD:EE:99\"}]}}"

echo "  Waiting for reconciliation after sentinel MAC..."
STATUS=""
for i in $(seq 1 30); do
  STATUS=$(kubectl get ciliumvtepconfig zone-a \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  if [ "$STATUS" = "True" ]; then break; fi
  sleep 2
done

if [ "$STATUS" = "True" ]; then
  pass "zone-a CRD status is Ready after MAC patch"
else
  fail "zone-a CRD status not Ready after MAC patch: $STATUS"
fi

echo "  Verifying BPF map updated on worker..."
VTEP_UPDATED=$(vtep_bpf_list "kind-worker")
# Check for updated MAC (case-insensitive since BPF map lowercases MACs)
if echo "$VTEP_UPDATED" | jq -r 'to_entries[].value[]' 2>/dev/null | grep -iq "vtepmac=aa:bb:cc:dd:ee:99"; then
  pass "BPF map on kind-worker reflects sentinel MAC"
else
  fail "BPF map MAC not updated. Got: $VTEP_UPDATED"
fi

# Restore the real MAC so connectivity tests in this phase (and Phase 5) succeed.
# A wrong inner destination MAC causes the VXLAN responder's kernel to drop frames.
echo "  Restoring real MAC ($REAL_MAC_A) for connectivity verification..."
kubectl patch ciliumvtepconfig zone-a --type=merge -p "{
  \"spec\": {\"endpoints\": [{\"name\": \"router-a\", \"cidr\": \"10.1.5.0/24\",
    \"tunnelEndpoint\": \"$VTEP_A_IP\", \"mac\": \"$REAL_MAC_A\"}]}}"

echo "  Waiting for reconciliation after MAC restore..."
STATUS=""
for i in $(seq 1 30); do
  STATUS=$(kubectl get ciliumvtepconfig zone-a \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  if [ "$STATUS" = "True" ]; then break; fi
  sleep 2
done

echo "  Verifying connectivity works after MAC restore..."
if kubectl exec probe-zone-a -- ping -c 3 -W 5 10.1.5.1; then
  pass "zone-a connectivity works after MAC restore"
else
  fail "zone-a connectivity broken after MAC restore"
fi

fi # end REAL_MAC_A check

# zone-b: same sentinel MAC test mirrored on kind-worker2 / vtep-responder-b
REAL_MAC_B=$(docker exec vtep-responder-b cat /sys/class/net/vxlan0/address 2>/dev/null || echo "")
if [ -z "$REAL_MAC_B" ]; then
  fail "Could not read real MAC from vtep-responder-b — skipping zone-b dynamic update test"
else

echo "  Patching zone-b config with a sentinel MAC to verify BPF update..."
kubectl patch ciliumvtepconfig zone-b --type=merge -p "{
  \"spec\": {\"endpoints\": [{\"name\": \"router-b\", \"cidr\": \"10.1.5.0/24\",
    \"tunnelEndpoint\": \"$VTEP_B_IP\", \"mac\": \"AA:BB:CC:DD:EE:88\"}]}}"

echo "  Waiting for reconciliation after sentinel MAC..."
STATUS=""
for i in $(seq 1 30); do
  STATUS=$(kubectl get ciliumvtepconfig zone-b \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  if [ "$STATUS" = "True" ]; then break; fi
  sleep 2
done

if [ "$STATUS" = "True" ]; then
  pass "zone-b CRD status is Ready after MAC patch"
else
  fail "zone-b CRD status not Ready after MAC patch: $STATUS"
fi

echo "  Verifying BPF map updated on worker2..."
VTEP_UPDATED_B=$(vtep_bpf_list "kind-worker2")
if echo "$VTEP_UPDATED_B" | jq -r 'to_entries[].value[]' 2>/dev/null | grep -iq "vtepmac=aa:bb:cc:dd:ee:88"; then
  pass "BPF map on kind-worker2 reflects sentinel MAC"
else
  fail "BPF map MAC not updated. Got: $VTEP_UPDATED_B"
fi

echo "  Restoring real MAC ($REAL_MAC_B) for connectivity verification..."
kubectl patch ciliumvtepconfig zone-b --type=merge -p "{
  \"spec\": {\"endpoints\": [{\"name\": \"router-b\", \"cidr\": \"10.1.5.0/24\",
    \"tunnelEndpoint\": \"$VTEP_B_IP\", \"mac\": \"$REAL_MAC_B\"}]}}"

echo "  Waiting for reconciliation after MAC restore..."
STATUS=""
for i in $(seq 1 30); do
  STATUS=$(kubectl get ciliumvtepconfig zone-b \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  if [ "$STATUS" = "True" ]; then break; fi
  sleep 2
done

echo "  Verifying connectivity works after MAC restore..."
if kubectl exec probe-zone-b -- ping -c 3 -W 5 10.1.5.1; then
  pass "zone-b connectivity works after MAC restore"
else
  fail "zone-b connectivity broken after MAC restore"
fi

fi # end REAL_MAC_B check

# ── Phase 5: CRD Deletion ──────────────────────────────────

phase 5 "CRD Deletion"

echo "  Deleting zone-a config..."
kubectl delete ciliumvtepconfig zone-a

echo "  Waiting for BPF map cleanup..."
COUNT=1
for i in $(seq 1 15); do
  VTEP_AFTER=$(vtep_bpf_list "kind-worker")
  COUNT=$(bpf_entry_count "$VTEP_AFTER")
  if [ "$COUNT" -eq 0 ]; then break; fi
  sleep 2
done

if [ "$COUNT" -eq 0 ]; then
  pass "kind-worker BPF map cleared after CRD deletion"
else
  fail "kind-worker still has $COUNT VTEP entries after delete. Got: $VTEP_AFTER"
fi

echo "  Verifying zone-b still works..."
if kubectl exec probe-zone-b -- ping -c 3 -W 5 10.1.5.1; then
  pass "zone-b connectivity unaffected by zone-a deletion"
else
  fail "zone-b connectivity broken after zone-a deletion"
fi

# ── Summary ─────────────────────────────────────────────────

echo ""
echo "========================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
