# Cilium Network Driver

Cilium Network Driver allows cilium-agent to expose network devices directly
to pods, without those pods participating in the Cilium fabric. The driver
registers as a
[DRA](https://kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/)
plugin and publishes `ResourceSlice` resources to the Kubernetes API so pods
can claim devices via the standard DRA framework.

## Requirements

- Kubernetes v1.34+
- Cilium agent with `--enable-cilium-network-driver` (set automatically
  when the Helm flag is enabled)

## Use cases

Applications that need direct network device access on a separate network
plane from the Cilium-managed pod network and/or physical device
hand-off from the host, such as:

- DPDK-based applications (VNFs, packet-processing pipelines)
- High-frequency trading or other low-latency workloads

## Device Managers

A Device Manager implements the `types.DeviceManager` interface and is
responsible for discovering and lifecycle-managing a class of network device.
Each manager runs as a long-lived goroutine: it calls `publish(devices)`
whenever the device set changes, then blocks until context cancellation.

Available device managers:

| Manager  | Key in CRD | Devices managed                       |
|----------|------------|---------------------------------------|
| `sriov`  | `sriov`    | SR-IOV Virtual Functions (legacy VFs) |
| `dummy`  | `dummy`    | Linux dummy interfaces                |

### SR-IOV device manager

The SR-IOV manager (`pkg/networkdriver/sriov`) discovers VFs by walking
`/host/sys/bus/pci/devices`, filtering for Ethernet-class PCI devices
(`class=0x0200`) that are SR-IOV Virtual Functions (i.e. have a `physfn`
symlink). For each matching VF it records:

- PCI address (`Addr`) — used as the stable `IfName()` (colons and dots
  replaced with dashes, e.g. `0000-03-00-1`)
- Kernel interface name (`KernelIfaceName`) — populated when the VF has a
  kernel netdev bound (empty for DPDK/vfio-bound VFs)
- Physical Function kernel interface name (`PFName`) and VF index (`VFID`) —
  used by `Setup` to configure VLAN and by `Free` to reset it
- PCI vendor/device ID and kernel driver

VF count provisioning (`sriov_numvfs`) is handled at startup by `setupVFs`:
if a PF already has VFs configured (non-zero `sriov_numvfs`) the manager
leaves them untouched and logs a warning if the count differs from config.
If the PF has no VFs, the manager writes the requested count to
`sriov_numvfs`.

The manager publishes the discovered VF list once at startup, then blocks
until context cancellation. It does not re-scan at runtime; a VF set that
changes while the agent is running requires an agent restart.

### Dummy device manager

The dummy manager (`pkg/networkdriver/dummy`) synthesises Linux dummy
interfaces named `dummy0`…`dummy<N-1>` from the configured `count`. Actual
link creation is deferred to `Setup` (called at `PrepareResourceClaims` time).
The manager publishes the synthesised device list once at startup and then
blocks.

## State management — statedb

All device state is tracked in a single [statedb](https://github.com/cilium/statedb)
table named **`networkdriver-dra-devices`** (type `statedb.RWTable[*DRADevice]`).
The table is the single observable source of truth for both discovery state
and allocation state and is inspectable at runtime via `cilium-dbg statedb`.

### DRADevice schema

| Field       | Type                  | Description                                                     |
|-------------|-----------------------|-----------------------------------------------------------------|
| `Name`      | `string`              | Device name assigned by the manager (primary key component)     |
| `Pool`      | `string`              | Pool the device was assigned to (primary key component)         |
| `Manager`   | `DeviceManagerType`   | Which manager owns this device (`sr-iov`, `dummy`, …)           |
| `Dev`       | `types.Device`        | Opaque device object (marshalled to ResourceClaim status)       |
| `Attrs`     | `part.Map[…]`         | Attributes published in the ResourceSlice                       |
| `PodUID`    | `kube_types.UID`      | UID of the pod holding the device; empty when free              |
| `ClaimUID`  | `kube_types.UID`      | UID of the ResourceClaim; empty when free                       |
| `Config`    | `types.DeviceConfig`  | Device config from the claim (e.g. `PodIfName`, `Vlan`)        |

Primary key: `"<pool>/<name>"` — enables O(log n) prefix scans over all
devices in a pool via `DevicesByPool`.

### How state flows

```
Device manager goroutine
  └─ Run(ctx, publish)
       └─ publish([]types.Device)     ← called once at startup; again on any change
            └─ onDevices()            ← driver callback registered with the manager
                 ├─ builds pool assignment for each device (resolvePoolAssignments)
                 └─ writes rows to the table via Modify (WriteTxn)
                      • new row  → stored directly with allocation fields from
                                   restoreDevicesFromClaim (post-restart path)
                      • existing → merge fn preserves PodUID/ClaimUID/Config,
                                   updates Dev/Attrs from the new scan

PrepareResourceClaims (kubelet → DRA plugin)
  └─ commitAllocation(podUID, claimUID, allocs)
       ├─ writes to driver.allocations (in-memory, for fast lookup)
       └─ setAllocationInTable()      ← stamps PodUID/ClaimUID/Config on table rows

UnprepareResourceClaims (kubelet → DRA plugin)
  └─ removeAllocation(claimUID)
       ├─ removes from driver.allocations
       └─ setAllocationInTable(clearing=true)  ← clears PodUID/ClaimUID/Config

Agent restart
  └─ restoreDevicesFromClaim()        ← reads ResourceClaim status from API server
       └─ rebuilds driver.allocations
            └─ (next onDevices call)  ← stamps allocation fields onto new table rows
```

Key invariants:

- `onDevices` is the only writer of discovery fields (`Dev`, `Attrs`, `Pool`).
- `setAllocationInTable` is the only writer of allocation fields
  (`PodUID`, `ClaimUID`, `Config`).
- Allocation writes do **not** trigger a re-publish of the ResourceSlice —
  allocation state is internal to the driver and not part of the DRA API.
- The table outlives individual publish cycles; rows are never deleted unless
  the device manager stops reporting a device.

### Inspecting state at runtime

```bash
# Dump the full statedb as JSON (includes all tables)
kubectl -n kube-system exec <cilium-pod> -c cilium-agent -- cilium-dbg statedb

# Pretty-print device table
kubectl -n kube-system exec <cilium-pod> -c cilium-agent -- \
  cilium-dbg statedb | python3 -c "
import sys, json
rows = json.load(sys.stdin).get('networkdriver-dra-devices', [])
for r in rows:
    alloc = r['PodUID'] or '(free)'
    print(f\"{r['Pool']}/{r['Name']}  manager={r['Manager']}  pod={alloc}\")
"
```

Example output while a VF is allocated to a pod:

```
rn-sriov/0000-03-00-4  manager=sr-iov  pod=(free)
rn-sriov/0000-03-00-5  manager=sr-iov  pod=a1b2c3d4-…
rn-sriov/0000-03-00-6  manager=sr-iov  pod=(free)
rn-sriov/0000-03-00-7  manager=sr-iov  pod=(free)
```

## How to use the Network Driver

### 1. Enable the feature

The DRA framework, NRI (CRI integration hook), and device discovery require
host mounts that are not needed by any other Cilium feature. The Network
Driver must therefore be explicitly enabled:

```bash
helm upgrade cilium cilium/cilium \
  --set networkDriver.enabled=true
```

This sets `--enable-cilium-network-driver` on the agent.

### 2. Provide a node configuration

The agent reads its configuration from a `CiliumNetworkDriverNodeConfig` CRD
whose `metadata.name` matches the node hostname.

**Minimal example — dummy devices (3 devices):**

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name: worker-node-1        # must match node hostname
spec:
  driverName: "networkdriver.cilium.io"  # optional; this is the default
  deviceManagerConfigs:
    dummy:
      enabled: true
      count: 3          # number of dummy links to create and advertise
  pools:
    - name: fast-net
      filter:
        deviceManagers:
          - dummy
```

**SR-IOV example — 4 VFs on ens1f0:**

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name: worker-node-1
spec:
  driverName: "networkdriver.cilium.io"
  deviceManagerConfigs:
    sriov:
      enabled: true
      ifaces:
        - ifName: ens1f0
          vfCount: 4
  pools:
    - name: sriov-pool
      filter:
        deviceManagers:
          - sr-iov
        pfNames:
          - ens1f0
```

#### Pool filters

Pools group devices that share a common purpose. Only devices matched by
the pool's filter are advertised in the corresponding `ResourceSlice`.
All specified filter fields are ANDed together.

| Filter field     | SR-IOV                                                                                  | Dummy                                   |
|------------------|-----------------------------------------------------------------------------------------|-----------------------------------------|
| `deviceManagers` | Match when set to `sr-iov`                                                              | Match when set to `dummy`               |
| `ifNames`        | Kernel interface name of the VF (empty for DPDK/vfio devices — use `pciAddrs` instead) | Kernel interface name of the dummy link |
| `pfNames`        | Physical Function kernel interface name                                                 | Ignored — dummy devices always match    |
| `parentIfNames`  | Ignored — SR-IOV devices always match                                                   | Not applicable (non-empty → no match)   |
| `pciAddrs`       | PCI address of the VF (e.g. `0000:03:00.1`)                                            | Not applicable (non-empty → no match)   |
| `vendorIDs`      | PCI vendor ID                                                                           | Not applicable (non-empty → no match)   |
| `deviceIDs`      | PCI device ID                                                                           | Not applicable (non-empty → no match)   |
| `drivers`        | Kernel driver bound to the VF (e.g. `mlx5_core`, `vfio-pci`)                          | Not applicable (non-empty → no match)   |

#### Filter conflict rules

Filters are validated at configuration load time and enforced at runtime.

**Config-time validation** rejects a configuration with duplicate pool names or
where the same `ifNames` value appears across more than one pool, since that
field uniquely identifies a single device.

**Runtime conflict resolution** handles cases where a device matches more than
one pool despite passing config-time validation (e.g. when pools overlap via
`pfNames`, `drivers`, or `vendorIDs`). The device is assigned to exactly one
pool using the following priority:

1. **Previous assignment** — if the device was assigned to a pool in a prior
   publish and that pool still matches the device, the assignment is
   kept unchanged. This ensures stability across publishes.
2. **Alphabetically first matching pool** — deterministic tie-break for devices
   that have no prior assignment.

An error is logged whenever a device matches more than one pool.

#### Device configuration options

Device-specific configuration is passed as opaque parameters in the
`ResourceClaim` (see step 3). Supported fields (from `types/types.go`):

| Field       | Type     | Description                                              |
|-------------|----------|----------------------------------------------------------|
| `vlan`      | `int32`  | 802.1q VLAN ID to configure on the device (SR-IOV only)  |
| `podIfName` | `string` | Rename the interface inside the pod namespace            |

### 3. Prepare device requests

Create a `DeviceClass` to encapsulate device selection logic:

```yaml
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: sriov-pool.networkdriver.cilium.io
spec:
  selectors:
  - cel:
      expression: >
        device.driver == "networkdriver.cilium.io" &&
        device.attributes["networkdriver.cilium.io"].pool == "sriov-pool"
```

Create a `ResourceClaimTemplate` that references the class and passes device
configuration as opaque parameters:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: sriov-claim
spec:
  spec:
    devices:
      requests:
      - name: net
        exactly:
          deviceClassName: sriov-pool.networkdriver.cilium.io
      config:
      - requests:
          - net
        opaque:
          driver: networkdriver.cilium.io
          parameters:
            vlan: 1001
            podIfName: sriov0
```

Alternatively, skip the `DeviceClass` and match directly via CEL:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: sriov-claim-direct
spec:
  spec:
    devices:
      requests:
      - name: net
        exactly:
          selectors:
          - cel:
              expression: >
                device.driver == "networkdriver.cilium.io" &&
                device.attributes["networkdriver.cilium.io"].pool == "sriov-pool"
      config:
      - requests:
          - net
        opaque:
          driver: networkdriver.cilium.io
          parameters:
            podIfName: sriov0
            vlan: 1001
```

### 4. Request a device from a pod

Reference the `ResourceClaimTemplate` in the pod spec:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: dpdk-app
spec:
  resourceClaims:
  - name: net
    resourceClaimTemplateName: sriov-claim-direct
  containers:
  - name: app
    image: my-dpdk-app:latest
```

## Verifying the setup

### Check node configuration was applied

```bash
# List all per-node configurations
kubectl get ciliumnetworkdrivernodeconfigs

# Inspect the configuration for a specific node
kubectl get ciliumnetworkdrivernodeconfig worker-node-1 -o yaml
```

### Verify published devices (ResourceSlices)

```bash
# List all ResourceSlices published by the network driver
kubectl get resourceslice

# Inspect a specific slice
kubectl get resourceslice <name> -o yaml
```

Example output:
```
NAME                                              NODE           DRIVER                    POOL         AGE
worker-node-1-networkdriver.cilium.io-abc12   worker-node-1  networkdriver.cilium.io   sriov-pool   30s
```

### Verify ResourceClaims and allocations

```bash
# List all resource claims
kubectl get resourceclaims -A

# Check claim status (allocated, reserved, device status)
kubectl get resourceclaim <name> -n <namespace> -o yaml

# List claim templates
kubectl get resourceclaimtemplates -A
```

### Verify DeviceClasses

```bash
kubectl get deviceclasses
```

### Inspect device and allocation state

```bash
# Dump the statedb table — shows every device and its current allocation
kubectl -n kube-system exec <cilium-pod> -c cilium-agent -- cilium-dbg statedb
```

The `networkdriver-dra-devices` table is printed in tabular form with columns:
`Name`, `Manager`, `Pool`, `PodUID`, `ClaimUID`, `PodIfName`. A non-empty
`PodUID` means the device is currently prepared for that pod. All fields are
empty for free devices.

## Feature status

Experimental. The API and configuration format may change between releases.
