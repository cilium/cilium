# Cilium Network Driver

Cilium Network Driver allows cilium-agent to expose network devices directly
to pods, without those pods participating in the Cilium fabric. The driver
registers as a
[DRA](https://kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/)
plugin and publishes `ResourceSlice` resources to the Kubernetes API so pods
can claim devices via the standard DRA framework.

## Requirements

- Kubernetes v1.34+
- Container Runtime NRI support (and have it enabled). The agent 
  depends on `/var/run/nri/nri.sock` for plugin registration.
- Cilium agent with `--enable-network-driver` (set automatically
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

| Manager         | Key in CRD     | `DeviceManagerType` string | Devices managed                                          |
|-----------------|----------------|----------------------------|-----------------------------------------------------------|
| `sriov`         | `sriov`        | `sr-iov`                   | SR-IOV Virtual Functions (legacy mode)                    |
| `dummy`         | `dummy`        | `dummy`                    | Linux dummy interfaces                                    |

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

VLAN isolation is enforced directly via `ndo_set_vf_vlan` on the PF
(`LinkSetVfVlan`).

VF count provisioning (`sriov_numvfs`) is handled at startup: if a PF already
has VFs configured (non-zero `sriov_numvfs`) the manager leaves them
untouched and logs a warning if the count differs from config. If the PF has
no VFs, the manager writes the requested count to `sriov_numvfs`.

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
table named **`networkdriver-dra-devices`** (type `statedb.RWTable[*DRADevice]`,
`pkg/networkdriver/tables.go`). The table is the single observable source of
truth for both discovery state and allocation state and is inspectable at
runtime via `cilium-dbg statedb`.

### DRADevice schema

```go
type DRADevice struct {
    Name    string                  // primary key; assigned by the device manager
    Manager types.DeviceManagerType
    Dev     types.Device            // opaque device handle (marshalled to ResourceClaim status)

    // Allocation fields — non-zero only when the device is prepared for a pod.
    Pool     string
    PodUID   kube_types.UID
    ClaimUID kube_types.UID
    Config   types.DeviceConfig
}
```

| Field      | Type                 | Description                                                                                                   |
|------------|----------------------|-----------------------------------------------------------------------------------------------------------------|
| `Name`     | `string`             | Device name assigned by the manager; **the primary key**. Not necessarily the kernel ifname.                    |
| `Manager`  | `DeviceManagerType`  | Which manager owns this device (`sr-iov`, `dummy`, …)                                                          |
| `Dev`      | `types.Device`       | Opaque device object; attributes for the `ResourceSlice` are computed on demand from `Dev.GetAttrs()`, not cached in the row |
| `Pool`     | `string`             | Set only once the device is allocated (`ClaimUID`/`PodUID` non-empty), to pin it to that pool across restarts/re-publishes; empty when free — see below |
| `PodUID`   | `kube_types.UID`     | UID of the pod holding the device; empty when free                                                              |
| `ClaimUID` | `kube_types.UID`     | UID of the ResourceClaim; empty when free                                                                       |
| `Config`   | `types.DeviceConfig` | Device config from the claim (e.g. `PodIfName`, `Vlan`)                                                        |

There is no separate `Attrs` field: `ResourceSlice` attributes are built
fresh on every publish from `Dev.GetAttrs()`, plus two injected labels —
`pool` and `deviceManager` (`types.PoolNameLabel`/`types.DeviceManagerLabel`).

### How state flows

Pool membership is **not** cached at write time for free devices — it's
resolved on demand every time the `ResourceSlice` is (re)built:

```
Device manager goroutine
  └─ Run(ctx, publish)
       └─ publish([]types.Device)   ← called once at startup; again on any change
            └─ driver.onDevices()   ← callback registered per manager with the driver
                 ├─ writes/updates rows for this manager's devices (Modify, WriteTxn)
                 │    • new row  → Name/Manager/Dev only; allocation fields
                 │                 stay zero unless a prior restoreDevicesFromClaim
                 │                 already populated this row
                 │    • existing → Dev updated (dev.Merge(old.Dev) carries forward
                 │                 fields the fresh scan couldn't re-resolve, e.g. a
                 │                 VF's KernelIfaceName once it's inside a pod netns);
                 │                 Pool/PodUID/ClaimUID/Config left untouched
                 └─ deletes rows for this manager's devices no longer reported

PrepareResourceClaim (kubelet → DRA plugin)
  └─ driver.setAllocationInTable(allocs, podUID, claimUID)
       └─ stamps PodUID/ClaimUID/Config/Pool directly on the matching table rows
          (no separate in-memory allocation cache — statedb is the only store)

UnprepareResourceClaim (kubelet → DRA plugin)
  └─ looks up devices via DevicesByClaimUID
     then driver.clearAllocationInTable(allocs)
        └─ then calls Device.Free() per device
            └─ clears PodUID/ClaimUID/Config

Building a ResourceSlice (on every publish)
  └─ driver.buildPoolsFromTable()
       └─ for each row:
            • if allocated (ClaimUID/PodUID set): keep its existing Pool
              unchanged, so a device already claimed from a pool is never
              silently reassigned while pools/filters are being re-evaluated
            • if free: driver.resolvePool(dev, sortedPools) re-evaluates every
              configured pool's filter against Dev.Match(filter) and picks the
              (deterministic, alphabetically-first) matching pool fresh each time
       └─ attrs := Dev.GetAttrs(); attrs["pool"], attrs["deviceManager"] injected
       └─ assembled into resourceslice.Pool per pool name

Agent restart
  └─ restoreDevices()                 ← lists local pods' ResourceClaimStatuses
       └─ restoreDevicesFromClaim()   ← per claim, rebuilds the device via
                                         devMgr.RestoreDevice() and Inserts a
                                         fully-populated row (Dev + PodUID +
                                         ClaimUID + Config + Pool) directly,
                                         ahead of that manager's first onDevices call
```

Key invariants:

- `onDevices` is the only writer of `Dev` (and hence discovery-derived
  attributes); it never touches allocation fields.
- `setAllocationInTable`/`clearAllocationInTable` are the only writers of
  allocation fields (`PodUID`, `ClaimUID`, `Config`, `Pool`).
- Allocation writes do **not** trigger a re-publish of the `ResourceSlice` —
  allocation state is internal to the driver and not part of the DRA API;
  the next natural publish (or restart) picks it up.
- The table outlives individual publish cycles; rows are never deleted
  unless the owning device manager stops reporting that device.

### Inspecting state at runtime

```bash
# Dump the full statedb as JSON (includes all tables)
kubectl -n kube-system exec <cilium-pod> -c cilium-agent -- cilium-dbg statedb
```

Example output while a VF is allocated to a pod:

```
0000-03-00-4  manager=sr-iov  pool=(unresolved)  pod=(free)
0000-03-00-5  manager=sr-iov  pool=sriov-pool     pod=a1b2c3d4-…
0000-03-00-6  manager=sr-iov  pool=(unresolved)  pod=(free)
0000-03-00-7  manager=sr-iov  pool=(unresolved)  pod=(free)
```

Free devices show `pool=(unresolved)` if they were never allocated. Note
that `Pool` is only *cleared* by `clearAllocationInTable`'s counterpart
`setAllocationInTable` writing a new value — freeing a device
(`clearAllocationInTable`) resets `PodUID`/`ClaimUID`/`Config` but does
**not** reset `Pool`, so a device that was previously allocated and is now
free may still show its last-held `pool` value even though `pod=(free)`.
The table's `Pool` field for a free device is therefore stale/meaningless —
its actual current pool membership is computed live by
`buildPoolsFromTable`/`resolvePool` at publish time, not read from the row.

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
whose `metadata.name` matches the cilium node name (from `CiliumNode`).
Note: at the current point in time, configuration updates need a restart
of the cilium-agent pod.

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name: worker-node-1        # must match CiliumNode name
spec:
  driverName: "networkdriver.cilium.io"  # optional; this is the default
  # Optional DRA plugin-registration retry tuning (all have defaults):
  draRegistrationRetryInterval: 1   # seconds between registration retries
  draRegistrationTimeout: 5         # seconds to wait for each attempt
  draRegistrationMaxAttempts: 10    # give up after this many attempts
  deviceManagerConfigs:
    ...
  pools:
    ...
```

**Minimal example — dummy devices (3 devices):**

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name: worker-node-1
spec:
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

**SR-IOV example — 4 VFs on ens1f0 (legacy mode):**

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name: worker-node-1
spec:
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
|------------------|-------------------------------------------------------------------------------------------|------------------------------------------|
| `deviceManagers` | Match when set to `sr-iov`                                                                | Match when set to `dummy`               |
| `ifNames`        | Kernel interface name of the VF (empty for DPDK/vfio-bound VFs, which have no kernel netdev; for a VF currently inside a pod netns, the last-known kernel ifname is preserved via `Merge` rather than cleared — use `pciAddrs` if you need a filter unaffected by this) | Kernel interface name of the dummy link |
| `pfNames`        | Physical Function kernel interface name                                                   | Ignored — dummy devices always match    |
| `parentIfNames`  | Ignored — devices always match regardless of this filter                                  | Not applicable (non-empty → no match)   |
| `pciAddrs`       | PCI address of the VF (e.g. `0000:03:00.1`)                                               | Not applicable (non-empty → no match)   |
| `vendorIDs`      | PCI vendor ID                                                                              | Not applicable (non-empty → no match)   |
| `deviceIDs`      | PCI device ID                                                                              | Not applicable (non-empty → no match)   |
| `drivers`        | Kernel driver bound to the VF (e.g. `mlx5_core`, `vfio-pci`)                              | Not applicable (non-empty → no match)   |

#### Filter conflict rules

Filters are validated at configuration load time and enforced at runtime.

**Config-time validation** rejects a configuration with duplicate pool names or
where the same `ifNames` value appears across more than one pool, since that
field uniquely identifies a single device.

**Runtime conflict resolution** handles cases where a device matches more than
one pool despite passing config-time validation (e.g. when pools overlap via
`pfNames`, `drivers`, or `vendorIDs`). The device is assigned to exactly one
pool using the following priority:

1. **Previous assignment (allocated devices only)** — if the device is
   currently allocated to a pod (`PodUID`/`ClaimUID` set), its existing
   `Pool` is kept unchanged for as long as that allocation lasts, regardless
   of how filters re-evaluate in the meantime. This pinning does **not**
   apply to free devices — a free device has no sticky pool from a past
   allocation; it's always re-evaluated fresh (see rule 2).
2. **Alphabetically first matching pool** — deterministic tie-break, applied
   fresh on every publish for any device that is not currently allocated.

An error is logged whenever a device matches more than one pool.

#### Device configuration options

Device-specific configuration is passed as opaque parameters in the
`ResourceClaim` (see step 3). Supported fields (from `types/types.go`):

| Field       | Type     | Description                                                                 |
|-------------|----------|------------------------------------------------------------------------------|
| `vlan`      | `int32`  | 802.1q VLAN ID to configure on the device (SR-IOV only)                      |
| `podIfName` | `string` | Rename the interface inside the pod namespace                               |

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
# cilium-dbg statedb always dumps JSON — same command as the "Inspecting
# state at runtime" section above, see that section for a way to pretty-print it.
kubectl -n kube-system exec <cilium-pod> -c cilium-agent -- cilium-dbg statedb
```

Each row includes `Name`, `Manager`, `Dev`, `PodUID`, `ClaimUID`, `Config`,
and `Pool`. A non-empty `PodUID` means the device is currently prepared for
that pod; `PodUID`/`ClaimUID`/`Config` are empty for free devices, but note
`Pool` is **not** reset when a device is freed (see the caveat above) — treat
`Pool` as meaningful only while `PodUID`/`ClaimUID` are also set.

## Feature status

Experimental. The API and configuration format may change between releases.
