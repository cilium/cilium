# VTEP CRD Integration Test Guide

## Overview

The VTEP CRD test suite validates that VTEP Custom Resources correctly program BPF LPM trie maps and establish VXLAN tunnels to external VTEP endpoints. It runs on a Kind cluster with Docker-based VTEP responder containers.

VTEP uses a **two-CRD model** (apiVersion `cilium.io/v2alpha1`, both cluster-scoped):

- **`CiliumVTEPConfig`** — the user-authored desired state. It carries a `nodeSelector` and a list of `vtepEndpoints`. It has **no** `.status`.
- **`CiliumVTEPNodeConfig`** — one object **per node**, with `metadata.name == <node name>`. It is created by the **operator**, which resolves each `CiliumVTEPConfig`'s `nodeSelector` against the cluster nodes and writes a per-node config containing the endpoints that apply to that node. Its `.status` (Ready condition + per-endpoint statuses) is written by **that node's agent** after it syncs the BPF maps.

In short: the user writes `CiliumVTEPConfig`; the operator fans it out into `CiliumVTEPNodeConfig` objects; each agent reports readiness on its own node's `CiliumVTEPNodeConfig.status`.

## Prerequisites

- **Docker** (Docker Desktop or Docker Engine)
- **Kind** (Kubernetes in Docker) - `brew install kind`
- **Helm** v3 - `brew install helm`
- **kubectl** configured to talk to the Kind cluster

## Entry Points

There are two ways the suite runs:

- **CI workflow** — `.github/workflows/conformance-vtep.yaml` creates the Kind cluster, labels the worker nodes, installs Cilium with `vtep.enabled=true`, starts the responder containers, applies the manifests, and then runs the test script.
- **Test assertions** — `test/vtep/run-vtep-tests.sh` contains all the phased assertions and is invoked by the CI workflow. It assumes the cluster, responders, CRDs, and probe pods already exist. Override the responder IPs / docker network via the `VTEP_A_IP`, `VTEP_B_IP`, and `VTEP_NETWORK` environment variables when running it outside CI.

There is **no** `local-test.sh`; the responder containers and cluster are stood up by the workflow (and its composite actions), not by a standalone wrapper script.

## What the Test Validates

### Phase 0: BPF Map Reconciliation
- Waits for VTEP BPF entries to appear on worker nodes after CRD creation.

### Phase 1: BPF Map Verification (2 tests)
- Verifies `kind-worker` (zone-a) has correct tunnelEndpoint `172.20.1.10`
- Verifies `kind-worker2` (zone-b) has correct tunnelEndpoint `172.20.1.11`

### Phase 2: NodeSelector Filtering (1 test)
- Verifies `kind-control-plane` has 0 VTEP entries (no zone label = no match)

### Phase 3: Per-Node CiliumVTEPNodeConfig (6 tests)
- Operator created one `CiliumVTEPNodeConfig` per matching node: `kind-worker` (from zone-a) and `kind-worker2` (from zone-b) both exist.
- `kind-worker`'s `.spec.vtepEndpoints` resolved cidr `10.1.5.0/24` to the zone-a endpoint (`172.20.1.10`); `kind-worker2`'s to the zone-b endpoint (`172.20.1.11`).
- Each node config reports `.status.conditions[Ready] == True` (written by that node's agent).

### Phase 4: VXLAN Connectivity (6 tests)
- Pod in zone-a pings `10.1.5.1` via VXLAN tunnel to responder-a
- Pod in zone-b pings `10.1.5.1` via VXLAN tunnel to responder-b
- Traffic isolation: zone-a traffic reaches ONLY responder-a, NOT responder-b
- Traffic isolation: zone-b traffic reaches ONLY responder-b, NOT responder-a

### Phase 5: Dynamic CRD Update (6 tests)
- Patches zone-a `CiliumVTEPConfig` with a sentinel MAC, waits for `kind-worker`'s `CiliumVTEPNodeConfig` to report Ready, verifies the BPF map updates
- Restores real MAC, verifies connectivity recovers
- Same for zone-b against `kind-worker2`

### Phase 6: CRD Deletion (2 tests)
- Deletes zone-a `CiliumVTEPConfig`, verifies BPF map is cleaned up on `kind-worker`
- Verifies zone-b connectivity is unaffected by zone-a deletion

## Architecture

```
+------------------+     +------------------+     +------------------+
| kind-control-    |     | kind-worker      |     | kind-worker2     |
| plane            |     | zone=zone-a      |     | zone=zone-b      |
|                  |     |                  |     |                  |
| (no VTEP match)  |     | BPF: 10.1.5.0/24 |     | BPF: 10.1.5.0/24 |
|                  |     |  -> 172.20.1.10  |     |  -> 172.20.1.11  |
|                  |     |                  |     |                  |
| (no node config) |     | VTEPNodeConfig   |     | VTEPNodeConfig   |
|                  |     |  kind-worker     |     |  kind-worker2    |
|                  |     | [probe-zone-a]   |     | [probe-zone-b]   |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         +------------------------+------------------------+
                       external Docker Network (172.20.0.0/16)
                                  |
                  +---------------+----------------+
                  |                                |
         +--------+---------+             +--------+---------+
         | vtep-responder-a |             | vtep-responder-b |
         | outer: 172.20.   |             | outer: 172.20.   |
         |        1.10      |             |        1.11      |
         | inner: 10.1.5.1  |             | inner: 10.1.5.1  |
         | VXLAN VNI: 2     |             | VXLAN VNI: 2     |
         +------------------+             +------------------+
```

## CRD Structures

### CiliumVTEPConfig (user-authored, no status)

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumVTEPConfig
metadata:
  name: zone-a
spec:
  nodeSelector:                          # Which nodes this config applies to
    matchLabels:
      topology.kubernetes.io/zone: "zone-a"
  vtepEndpoints:
    - name: router-a                     # Unique name within this config
      cidr: "10.1.5.0/24"                # Destination CIDR to match
      tunnelEndpoint: "172.20.1.10"      # Remote VTEP IP (outer)
      mac: "AA:BB:CC:DD:EE:FF"           # Destination MAC for encapsulation
```

### CiliumVTEPNodeConfig (operator-created, one per node, agent writes status)

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumVTEPNodeConfig
metadata:
  name: kind-worker                      # == node name
spec:
  vtepEndpoints:                         # resolved from matching CiliumVTEPConfigs
    - name: router-a
      cidr: "10.1.5.0/24"
      tunnelEndpoint: "172.20.1.10"
      mac: "AA:BB:CC:DD:EE:FF"
status:                                  # written by this node's agent after BPF sync
  conditions:
    - type: Ready
      status: "True"
  vtepEndpointStatuses:
    - ...
```

### Key Behaviors
- **nodeSelector**: Only nodes matching labels get a `CiliumVTEPNodeConfig` (and therefore BPF entries). Empty selector = all nodes.
- **Operator fan-out**: The operator resolves each `CiliumVTEPConfig`'s nodeSelector and creates/updates one `CiliumVTEPNodeConfig` per matching node, named after the node.
- **Agent-written status**: Readiness lives on `CiliumVTEPNodeConfig.status`, not on `CiliumVTEPConfig`. Check `.status.conditions[?(@.type=="Ready")].status` and `.status.vtepEndpointStatuses[]` on the per-node object.
- **Multiple CRDs**: Each `CiliumVTEPConfig` can target different node groups with different endpoints.
- **Same CIDR, different endpoints**: Different zones can route the same CIDR to different VTEPs.
- **Dynamic updates**: Editing a `CiliumVTEPConfig` spec re-resolves the affected node configs and updates BPF maps (no agent restart).

## Files

| File | Purpose |
|------|---------|
| `.github/workflows/conformance-vtep.yaml` | CI entry point - creates cluster, installs Cilium, starts responders, applies CRDs, runs tests |
| `test/vtep/run-vtep-tests.sh` | Phased test assertions (invoked by the CI workflow) |
| `test/vtep/manifests/zone-a-vtep.yaml` | CiliumVTEPConfig for zone-a nodes |
| `test/vtep/manifests/zone-b-vtep.yaml` | CiliumVTEPConfig for zone-b nodes |
| `test/vtep/manifests/probe-pods.yaml` | Test pods scheduled on worker nodes |

## How VTEP Responder Containers Work

The test creates two Docker containers (`vtep-responder-a`, `vtep-responder-b`) on the `external` Docker network (`172.20.0.0/16`) that simulate external VTEP endpoints:

1. Each container creates a VXLAN interface (`vxlan0`) pointing at the Kind worker nodes
2. The VXLAN interface is assigned the inner IP `10.1.5.1/24`
3. When a Cilium pod sends traffic to `10.1.5.1`, the BPF LPM trie matches `10.1.5.0/24`
4. Cilium encapsulates the packet in VXLAN and sends it to the configured tunnelEndpoint (`172.20.1.10` for zone-a, `172.20.1.11` for zone-b)
5. The responder decapsulates and replies

FDB/ARP entries are seeded on the responders so return traffic reaches the correct pod.

## Troubleshooting

### Check agent logs
```bash
kubectl -n kube-system logs -l k8s-app=cilium --tail=20
```

### Check operator logs
```bash
kubectl -n kube-system logs -l app.kubernetes.io/name=cilium-operator --tail=20
```

### Check CRD state
```bash
# User-authored desired state (no status)
kubectl get ciliumvtepconfigs -o wide
kubectl get ciliumvtepconfig zone-a -o yaml

# Per-node objects created by the operator; status lives here
kubectl get ciliumvtepnodeconfigs -o wide
kubectl get ciliumvtepnodeconfig kind-worker -o jsonpath='{.status}'
```

### Inspect BPF maps on a node
```bash
kubectl -n kube-system exec <cilium-pod> -- cilium-dbg bpf vtep list -o json
```

### Verify CRDs are registered
```bash
kubectl get crd ciliumvtepconfigs.cilium.io
kubectl get crd ciliumvtepnodeconfigs.cilium.io
```
