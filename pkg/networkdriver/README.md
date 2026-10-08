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

## State management — StateDB

The driver keeps live device inventory and prepared allocation state in two
[StateDB](https://github.com/cilium/statedb) tables. Device discovery can then
change without erasing the claim state needed to configure a pod or free a
device later. Both tables are visible through `cilium-dbg statedb`.

### Device inventory

`networkdriver-dra-devices` contains the devices currently reported by each
device manager:

```go
type DRADevice struct {
    Name    string
    Manager types.DeviceManagerType
    Dev     types.Device
}
```

`Name` is the primary key and the name published in a `ResourceSlice`. It
does not have to match a kernel interface name. `Manager` identifies the
device manager, and `Dev` is that manager's current device object.

Each device manager calls `onDevices` with its complete inventory. The driver
updates that manager's rows and removes devices it no longer reports. This
does not remove prepared allocation state. If the manager rediscovers a
prepared device, `Merge` preserves state that discovery can no longer see,
such as an SR-IOV Virtual Function interface name after the interface moved
into a pod network namespace.

`ResourceSlice` attributes are computed from `Dev.GetAttrs()` on each
publication. The driver also adds the `pool` and `deviceManager` attributes.

### Prepared allocations

`networkdriver-dra-allocations` contains devices that the driver prepared for
a Kubernetes Dynamic Resource Allocation (DRA) `ResourceClaim`:

```go
type DRAAllocation struct {
    DeviceName     string
    Manager        types.DeviceManagerType
    PreparedDevice types.Device
    Pool           string
    PodUID         kube_types.UID
    ClaimUID       kube_types.UID
    Config         types.DeviceConfig
}
```

The primary key is `AllocationKey(Pool, DeviceName)`. Secondary indexes
support lookups by claim UID, device name, and pod UID. `PreparedDevice`
holds the device state after setup, while `Config` records claim-specific
settings such as the pod interface name or VLAN.

The allocation table has a different lifetime from device inventory. An
inventory row answers, “What does the device manager see now?” An allocation
row answers, “What did the driver prepare, for which claim and pod, and what
state will it need for pod setup or cleanup?” Keeping those answers separate
prevents an inventory refresh from losing allocation state.

### Allocation lifecycle

```text
Device manager goroutine
  └─ Run(ctx, publish)
       └─ publish([]types.Device)
            └─ driver.onDevices()
                 ├─ merges prepared state found by device name
                 ├─ upserts Name/Manager/Dev in networkdriver-dra-devices
                 └─ removes missing inventory rows
                    (networkdriver-dra-allocations is unchanged)

PrepareResourceClaims (kubelet → DRA plugin)
  └─ for each scheduler-selected device
       ├─ reads the DRADevice from networkdriver-dra-devices
       ├─ calls Device.Setup(Config)
       ├─ serializes the prepared device to ResourceClaim.Status.Devices
       └─ after the status update, inserts a DRAAllocation in
          networkdriver-dra-allocations

RunPodSandbox (container runtime → NRI plugin)
  └─ finds allocations by PodUID
       └─ configures their devices in the pod network namespace

UnprepareResourceClaims (kubelet → DRA plugin)
  └─ finds allocations by ClaimUID
       └─ calls Device.Free(Config)
            ├─ success → deletes the DRAAllocation
            └─ failure → retains the row for a later retry

ResourceSlice publication (a change to either table wakes this loop)
  ├─ networkdriver-dra-devices
  │    └─ supplies the current device and its attributes
  ├─ networkdriver-dra-allocations
  │    └─ pins a prepared device to its recorded pool
  └─ buildPoolsFromTable()
       └─ draPlugin.PublishResources()

Agent restart
  ├─ local pods
  │    └─ resolve direct or template-generated ResourceClaims
  │         └─ ResourceClaim.Status.Devices
  │              └─ DeviceManager.RestoreDevice()
  │                   └─ rebuilds networkdriver-dra-allocations
  ├─ device managers rebuild networkdriver-dra-devices independently
  └─ DRA and NRI registration starts after both tables are initialized
```

The ResourceClaim status is the durable recovery record; both StateDB tables
are node-local runtime state. If the agent stops after `Device.Setup` but
before it updates the claim status, there is no serialized device state to
restore. The driver logs a warning on restart because that device may require
manual cleanup. If the status update succeeds but the agent stops before the
StateDB write, restart recovery can rebuild the allocation from the status.

Changes to either table trigger a new `ResourceSlice` publication. If one
device has allocation rows that name different pools, the state is ambiguous.
The driver logs the conflict and does not advertise that device.

### Inspecting state at runtime

```bash
kubectl -n kube-system exec <cilium-pod> -c cilium-agent -- \
  cilium-dbg statedb |
  jq '{
    inventory: .["networkdriver-dra-devices"] | map({Name, Manager}),
    allocations: .["networkdriver-dra-allocations"] |
      map({DeviceName, Manager, Pool, PodUID, ClaimUID, Config})
  }'
```

Example output for one prepared SR-IOV Virtual Function:

```json
{
  "inventory": [
    {
      "Name": "0000-03-00-1",
      "Manager": "sr-iov"
    }
  ],
  "allocations": [
    {
      "DeviceName": "0000-03-00-1",
      "Manager": "sr-iov",
      "Pool": "sriov-pool",
      "PodUID": "a1b2c3d4-...",
      "ClaimUID": "e5f6a7b8-...",
      "Config": {
        "podIfName": "sriov0",
        "vlan": 1001
      }
    }
  ]
}
```

An empty allocation list means StateDB currently tracks no prepared devices.
A retained allocation row can also indicate that cleanup failed; check the
agent log before treating it as an active pod allocation.

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

Per-node configs can be created directly (see below), or generated
automatically for groups of nodes by the operator from a
`CiliumNetworkDriverClusterConfig` — see
[Cluster-wide configuration](#cluster-wide-configuration-operator-driven).

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
`pfNames`, `drivers`, or `vendorIDs`). The driver normally assigns the
device to one pool using the following priority:

1. **Prepared allocation** — if the allocation table contains a row for the
   device, the recorded `Pool` is kept for as long as that allocation exists,
   regardless of how filters re-evaluate in the meantime. If multiple rows
   name different pools, the driver logs the conflict and does not advertise
   the device. Pool pinning does **not** apply after the final allocation row
   is removed.
2. **Alphabetically first matching pool** — deterministic tie-break, applied
   fresh on every publish for a device with no prepared allocation.

An error is logged whenever a device matches more than one pool.

#### Device configuration options

Device-specific configuration is passed as opaque parameters in the
`ResourceClaim` (see step 3). Supported fields (from `types/types.go`):

| Field       | Type     | Description                                                                 |
|-------------|----------|------------------------------------------------------------------------------|
| `vlan`      | `int32`  | 802.1q VLAN ID to configure on the device (SR-IOV only)                      |
| `podIfName` | `string` | Rename the interface inside the pod namespace                               |
| `interfaceSysctlIPv4` | `map[string]string` | Leaf sysctl parameters (e.g. `arp_filter`) applied under `net.ipv4.conf.<interface>.` for the allocated interface, once it is up in the pod netns |
| `interfaceSysctlIPv6` | `map[string]string` | Same as above, under `net.ipv6.conf.<interface>.`                    |


### Cluster-wide configuration (operator-driven)

Instead of (or in addition to) creating `CiliumNetworkDriverNodeConfig`
objects by hand per node, the cilium-operator can generate and manage them
for you from a cluster-scoped `CiliumNetworkDriverClusterConfig` CRD. This is
implemented in `operator/pkg/networkdriver/config` and is gated by the same
`--enable-network-driver` flag on the operator (`networkDriver.enabled=true`
via Helm also propagates to the operator).

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverClusterConfig
metadata:
  name: sriov-workers
spec:
  nodeSelector:            # optional; omit/nil to match all nodes
    matchLabels:
      node-role: sriov-worker
  spec:                    # a full CiliumNetworkDriverNodeConfigSpec
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

The operator watches `CiliumNode` objects and all
`CiliumNetworkDriverClusterConfig` objects, matches each node's labels
against each cluster config's `nodeSelector` (an empty/nil selector matches
every node), and creates/updates a `CiliumNetworkDriverNodeConfig` named
after the node for every match — mirroring `spec.spec` verbatim into the
generated node config's `.spec`. Deleting a `CiliumNetworkDriverClusterConfig`
(or a node no longer matching any selector) deletes the corresponding
generated `CiliumNetworkDriverNodeConfig` objects.

#### Conflict resolution

A node may only be governed by one cluster config at a time. When more than
one `CiliumNetworkDriverClusterConfig` selects the same node, priority is:

1. **Older `creationTimestamp` wins** — the earliest-created config that
   matches a node "occupies" it.
2. **Alphabetical name, as a tiebreak** — for configs created at the exact
   same time.

Every other cluster config that also matches an already-occupied node is
marked conflicting: `status.conditions` gets a
`cilium.io/ConflictingClusterConfiguration` condition
(`reason: configurationConflict`) set to `True`, and none of its nodes are
touched by that config (they keep whatever the winning config assigned, or
remain unconfigured if no non-conflicting config matches them). The
condition is cleared automatically once the conflict is resolved (e.g. the
higher-priority config is deleted or its selector no longer matches).

```bash
# See which cluster configs are active/conflicting and which nodes they cover
kubectl get ciliumnetworkdriverclusterconfigs
kubectl get ciliumnetworkdriverclusterconfig sriov-workers -o yaml   # check status.conditions

# See the node configs the operator generated (named after the node, not
# the cluster config, e.g. "worker-node-1" — not "sriov-workers")
kubectl get ciliumnetworkdrivernodeconfigs
kubectl get ciliumnetworkdrivernodeconfig worker-node-1 -o yaml
```

Manually created `CiliumNetworkDriverNodeConfig` objects for a node that
also matches a cluster config are treated as external drift: the operator's
reconciler owns that object once a cluster config selects the node, and
will overwrite/recreate it to match the cluster config's `spec.spec` (a
periodic 5-minute refresh additionally re-checks for such external changes,
independent of any Kubernetes watch event). Node configs whose node no
longer exists, or that no longer match any cluster config's node selector,
are deleted.

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
            interfaceSysctlIPv4:
              arp_filter: "1"
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

`networkdriver-dra-devices` shows current inventory.
`networkdriver-dra-allocations` shows prepared devices and any rows retained
for a failed cleanup attempt. See “State management — StateDB” above for the
field definitions and lifecycle.

## Feature status

Experimental. The API and configuration format may change between releases.
