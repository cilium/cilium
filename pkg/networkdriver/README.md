# Cilium Network Driver

Cilium Network Driver lets cilium-agent allocate network devices and hardware
resources to pods through Kubernetes Dynamic Resource Allocation (DRA). The
dummy and SR-IOV managers add separate interfaces to a pod. The RX queue
manager instead leases a physical receive queue to the pod's existing
Cilium-managed netkit interface. The driver registers as a
[DRA](https://kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/)
plugin and publishes `ResourceSlice` resources to the Kubernetes API so pods
can claim those resources through the standard DRA framework.

## Requirements

- Kubernetes v1.34+. Device managers that publish consumable capacity also
  require the `DRAConsumableCapacity` feature gate. Enable it explicitly on
  Kubernetes v1.34 and v1.35; it is enabled by default starting in v1.36.
- Container runtime with NRI support enabled. The agent
  depends on `/var/run/nri/nri.sock` for plugin registration.
- Container runtime CDI support. The agent writes CDI specifications to
  `/var/run/cdi` so DRA device metadata can be mounted into containers.
- Cilium agent with `--enable-network-driver` (set automatically
  when the Helm flag is enabled).
- The RX queue manager additionally requires a Linux kernel with netdev RX
  queue leasing and netkit support (upstream Linux v7.1 or an equivalent
  backport), a NIC driver that implements RX queue leasing, TCP header/data
  splitting, and ethtool flow-steering (ntuple) rules, Cilium's operational
  datapath mode set to `netkit` or `netkit-l2`, and XDP acceleration
  disabled. The kernel refuses most XDP programs on a device that splits
  headers or has an io_uring memory provider bound to one of its queues.

## Use cases

Applications that need direct device access, physical device hand-off, or a
dedicated receive queue on the Cilium-managed pod network, such as:

- DPDK-based applications (VNFs, packet-processing pipelines)
- High-frequency trading or other low-latency workloads
- Applications that consume a dedicated NIC receive queue, including
  `io_uring` zero-copy receive applications

## Device Managers

A Device Manager implements the `types.DeviceManager` interface and is
responsible for discovering and lifecycle-managing a class of network device.
Each manager runs as a long-lived goroutine: it calls `publish(devices)`
whenever the device set changes, then blocks until context cancellation.

Available device managers:

| Manager   | Key in CRD | `DeviceManagerType` string | Devices managed                                                 |
|-----------|------------|----------------------------|-----------------------------------------------------------------|
| `sriov`   | `sriov`    | `sr-iov`                   | SR-IOV Virtual Functions (legacy mode)                          |
| `dummy`   | `dummy`    | `dummy`                    | Linux dummy interfaces                                          |
| `rxqueue` | `rxQueue`  | `rxQueue`                  | Physical RX queues leased to existing Pod netkit interfaces     |

The dummy and SR-IOV managers publish dedicated devices. Each published dummy
device or SR-IOV Virtual Function can be allocated to one claim at a time. The
RX queue manager publishes each physical interface as a shareable device whose
capacity can be consumed by several claims.

### Device allocation model

A device manager controls how Kubernetes Dynamic Resource Allocation (DRA)
treats each device it publishes:

- `GetCapacity` returns the named capacity available on the device.
- `AllowMultipleAllocations` determines whether several independent claims
  may consume that capacity.
- `Setup` receives the allocation selected by the scheduler and returns the
  device prepared for that allocation.
- `Recover` re-creates missing kernel state for an allocation restored from
  `ResourceClaim` status. It must return the same logical allocation because
  recovery does not rewrite that status.
- `Free` receives the same allocation context during cleanup.

A dedicated device returns no consumable capacity and does not allow multiple
allocations. `Setup` may return the advertised device itself. This is the
existing model used by the dummy and SR-IOV managers.

A shareable device publishes capacity and sets `allowMultipleAllocations` in
its `ResourceSlice`. The Kubernetes scheduler may then allocate the same
published device to more than one `ResourceClaim`. Each allocation result has
a `ShareID` and the amount of capacity consumed by that share. The network
driver passes both values to the device manager; it does not choose the share
or perform the scheduler's capacity accounting.

`ShareID` describes the scheduler's allocation-time decision. A device's
sharing mode may change before preparation or recovery, so device managers
must interpret the allocation from `ShareID`, not from the device's current
`AllowMultipleAllocations` value.

```text
ResourceSlice device
  ├─ attributes
  ├─ capacity
  └─ allowMultipleAllocations
               │
               │ Kubernetes scheduler
               ▼
ResourceClaim allocation result
  ├─ pool + device
  ├─ shareID
  └─ consumedCapacity
               │
               │ PrepareResourceClaims
               ▼
DRAAllocation
  ├─ advertised device identity
  ├─ scheduler allocation identity and capacity
  └─ allocation-specific prepared device
```

`ShareID` distinguishes allocations of the same advertised device. It is not
a physical subdevice identifier. The device manager decides how the consumed
capacity maps onto hardware and may return a different prepared device for
each share.

The driver rejects shareable devices on Kubernetes versions older than v1.34.
It cannot inspect the API server's feature-gate configuration. On v1.34 or
later with `DRAConsumableCapacity` disabled, `ResourceSlice` publication
reports an error when the API server omits the feature-gated fields.

### RX queue device manager

The RX queue manager (`pkg/networkdriver/rxqueue`) publishes one shareable DRA
device for each configured physical interface. Its `rxQueues` capacity is the
number of queues configured for reservation. Each claim consumes exactly one
unit of that capacity. Kubernetes schedules capacity from the parent device;
physical queue IDs remain an implementation detail of the manager.

RX queue leasing requires Cilium-managed `kubernetes` or `cluster-pool` IPAM.
The Network Driver rejects other IPAM modes when the RX queue manager is
enabled. Cilium must control when a Pod address becomes available for reuse.

At startup, the manager resolves each configured interface and enumerates its
active RX queues through the netdev generic netlink API. The interface must be
up and must have more active queues than the configured reservation. The
manager selects the highest-numbered queues and always leaves at least one
queue outside the reserved set. `count` defaults to one. Discovery runs once,
so interface or queue-count changes require an agent restart.

Before it publishes the queues, the manager prepares each NIC. It removes the
reserved queues from the main RSS indirection table and spreads their entries
over the queues RSS already uses, keeping the hash key, the hash function, and
any queues the table already excluded. It then enables TCP header/data
splitting with a zero split threshold, which io_uring zero-copy receive
requires. Drivers that do not report their split setting are asked to enable
it anyway. mlx5 implements header/data splitting with hardware GRO, so if the
driver rejects the request the manager enables `rx-gro-hw`, which affects all
traffic on the NIC, and retries. The manager reads the settings back, and if
any NIC fails, it restores every NIC it changed. Repeating the preparation is
a no-op. Cilium does not revert these settings when cilium-agent stops, and
lowering `count` does not return queues to RSS.

At `PrepareResourceClaims` time, the manager selects an unleased physical
queue from the reserved set and records that reservation for the scheduler's
`ShareID`. It does not create a Pod interface or a kernel queue lease at this
point. DRA preparation may finish before CNI creates the Pod's primary
interface.

When the Network Driver is enabled, Cilium CNI creates each primary netkit
peer with two RX queue slots. Queue 0 carries the regular Cilium datapath;
queue 1 is available for a physical queue lease. CNI has created that
interface by the time NRI reports that the Pod sandbox started, and no
container runs until the NRI hook returns. For a Pod with a prepared RX queue
allocation, `RunPodSandbox` finds the CNI endpoint for that exact sandbox and
the interface named by `podIfName` (`eth0` by default). It verifies the Pod UID,
endpoint state, and network namespace cookie, then uses the addresses allocated
to that endpoint. Steering uses only these verified endpoint addresses. The driver
verifies that the interface is a netkit peer with room for a leased queue and
leases the reserved physical queue to queue 1. It reads the queue back and
verifies the target interface, network namespace, and virtual queue ID. A failed
lease fails sandbox creation, and kubelet retries it. NRI synchronization repeats
the lease for sandboxes that started while the agent was down.

NRI does not move, rename, or delete the netkit. CNI owns the interface and
the existing Cilium netkit datapath continues to handle ordinary traffic.
Only one RX queue allocation may target a given Pod interface.

Flow steering is reconciled separately. For every RX queue allocation, the
driver derives the destination IP, port, and protocol tuples from the verified
CNI attachment, allocation, and local Pod's named ports, and stores them
in the `networkdriver-rx-queue-flows` table. It recomputes a row when the Pod
or allocation changes, including a binding change with unchanged addresses.
A StateDB reconciler programs each row as ethtool flow-steering rules on the
physical NIC and retries failed rows with backoff.

The NIC is the source of truth for those rules. Reserved queues are excluded
from RSS and belong to the RX queue manager, so every rule whose action
delivers to one of them is managed by the driver, whatever the rule matches
on. The reconciler reads the rules back to adopt existing ones and removes
rules for the queue that are no longer desired. New rules go where the driver
chooses if it supports that, and otherwise in the lowest unused locations of
the rule table. The reconciler also re-applies every row periodically (every
30 minutes by default), which repairs rules changed outside Cilium.

io_uring zero-copy receive requires that only the steered flows reach a
leased queue. Cilium removes the reserved queues from the main RSS indirection
table at startup, but it does not check additional RSS contexts and does not
monitor RSS afterwards. While the RX queue manager is enabled, do not add
reserved queues back to the indirection table or create RSS contexts that
include them. Cilium does not detect or report traffic that reaches a leased
queue this way.

Do not apply ingress L7 policy or L7 visibility to a port selected by
`rxQueue`. Envoy terminates those connections and cannot read zero-copy
buffers, so requests fail. L7 proxying would also defeat zero copy, because
the application receives Envoy's connection rather than the NIC's traffic.

The queue reservation owns a queue's rules. Reserving a queue, programming its
rules, and releasing it all happen under the same lock, and a row's rules are
only programmed while the queue is still reserved for the row's share and
the row's attachment generation is current. Rules may only match addresses
that belong to that attachment. Replacing a sandbox invalidates the old
generation and removes its rules before creating the replacement lease. A
failed withdrawal leaves the attachment inactive for the lifetime of that
reservation. Reserving a queue also removes any rules left on it, for example
when cilium-agent stopped before it could free the previous allocation.

The manager adopts an identical existing lease and rejects a queue leased to
another interface or network namespace. Cleanup waits for CNI to remove the
primary netkit and release the kernel lease, removes the rules that target
the queue, and returns the physical queue to the manager's reserved pool.

After an agent restart, recovery restores the reservation for the physical
queue recorded in `PreparedDevice`. The kernel lease survives the restart.
The runtime attachment binding is not serialized. After Cilium restores its
endpoints, NRI synchronization validates the attachment before the flow
reconciler can program its rules.

Before IPAM releases an attachment's address, the network driver invalidates
its steering generation and synchronously removes its rules. A cleanup error
leaves the address allocated, even if endpoint deletion continues. Later release
attempts retry cleanup, including when the attachment's other address family is
released. Failed address releases are not automatically retried after endpoint
deletion. The address remains allocated until an explicit release succeeds or
cilium-agent restarts and startup recovery clears the stale rules.

NRI stop does not withdraw RX queue rules. If sandbox teardown stalls before
IPAM release, rules can remain installed, but the address remains allocated to
the old attachment. IPAM release, replacement binding, allocation cleanup, or
startup recovery removes those rules.

Before initializing IPAM, Cilium discovers physical queue leases from the
kernel and matches them to host-side netkit interfaces. It verifies ownership
through the attached Cilium programs and removes rules targeting those queues.
Leased queues with no steering rules need no cleanup and do not require that
ownership check. Unknown owners with rules, or failed rule queries, block startup.
This runs independently of the current Network Driver configuration.

Cilium owns all physical RX queue leases into its primary netkit interfaces.
Do not attach leases from another queue manager to those interfaces. Unknown
or ambiguous lease ownership blocks IPAM startup without deleting the rules.
The kernel hides leases on administratively down NICs; if Cilium cannot rule
out stale steering there, bring the NIC up so startup can inspect it. A cleanup
failure also blocks IPAM startup. These checks deliberately favor unavailable
addresses over premature reuse.

Agent restart withdraws and rebuilds steering, so acceleration can be briefly
interrupted. Queue leases and application registrations are not intentionally
destroyed by the startup sweep.

Kernel prerequisite: these checks assume successful rule withdrawal and queue
teardown actually prevent further DMA into the former provider. Linux 7.1.8
does not reliably report some queue-reconfiguration and mlx5 cleanup failures.
The software barriers cannot establish DMA isolation when the kernel reports
success without completing that work. That kernel contract remains unresolved.

### SR-IOV device manager

The SR-IOV manager (`pkg/networkdriver/sriov`) only manages the PFs listed in
`ifaces`. For each, it lists the PF's VFs from its `virtfnN` links under
`/host/sys/bus/pci/devices/<pf>`. VFs of PFs not listed in `ifaces` are not
discovered or modified. A configuration with no `ifaces` publishes no VFs.
For each VF it records:

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
device later. Both tables are visible through `cilium-dbg statedb`. RX queue
flow steering adds a third, derived table, `networkdriver-rx-queue-flows`,
described with the RX queue device manager.

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
does not remove prepared allocation state. For a dedicated device, `Merge`
preserves state that discovery can no longer see, such as an SR-IOV Virtual
Function interface name after the interface moved into a pod network
namespace. RX queue inventory represents the shared physical interface, so
the selected physical queue and target Pod interface remain solely in the
allocation table.

`ResourceSlice` attributes are computed from `Dev.GetAttrs()` on each
publication. The driver also adds the `pool` and `deviceManager` attributes.

### Prepared allocations

`networkdriver-dra-allocations` contains devices that the driver prepared for
a Kubernetes Dynamic Resource Allocation (DRA) `ResourceClaim`:

```go
type DRAAllocation struct {
    DeviceName       string
    Manager          types.DeviceManagerType
    PreparedDevice   types.Device
    LogicalPool      string
    PodUID           kube_types.UID
    ClaimUID         kube_types.UID
    Config           types.DeviceConfig
    ShareID          kube_types.UID
    ConsumedCapacity map[resourceapi.QualifiedName]apiresource.Quantity
}
```

`LogicalPool` is the user-configured Cilium pool (`spec.pools` in the CRD)
that the device matched at prepare time. It is published as the `pool` device
attribute so `DeviceClass` CEL selectors can match it. It is not the DRA
`ResourceSlice` pool name; each node publishes one DRA pool named after the
node.

The primary key is `AllocationKey(LogicalPool, DeviceName, ShareID)`. This
permits several prepared shares of one advertised device to coexist. Dedicated
allocations use an empty `ShareID` and still have one allocation row per
device. Secondary indexes support lookups by claim UID, device name, and pod
UID.

`ClaimUID` identifies the Kubernetes `ResourceClaim`. A non-empty `ShareID`
identifies one shared scheduler allocation; an empty value identifies a
dedicated allocation. `ConsumedCapacity` records the capacity assigned to the
share. `PreparedDevice` holds the current allocation-specific device returned
by `Setup` or `Recover`, while `Config` records driver settings such as the pod
interface name or VLAN.

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
                 ├─ for a dedicated allocation, merges prepared state found
                 │  by device name
                 ├─ leaves allocation-specific shares out of their parent
                 │  device's inventory state
                 ├─ upserts Name/Manager/Dev in networkdriver-dra-devices
                 └─ removes missing inventory rows
                    (networkdriver-dra-allocations is unchanged)

PrepareResourceClaims (kubelet → DRA plugin)
  └─ for each scheduler-selected device
       ├─ reads the DRADevice from networkdriver-dra-devices
       ├─ calls Device.Setup with Config, ShareID, and ConsumedCapacity
       ├─ receives the allocation-specific prepared device
       ├─ records ShareID in ResourceClaim.Status.Devices
       ├─ serializes the prepared device, Config, LogicalPool, and
       │  ConsumedCapacity into the status entry
       ├─ after the status update, inserts a DRAAllocation keyed by
       │  LogicalPool/DeviceName/ShareID in networkdriver-dra-allocations
       └─ returns the prepared device metadata to kubelet
            └─ the DRA helper writes a metadata file and CDI specification

RunPodSandbox (container runtime → NRI plugin)
  └─ finds allocations by PodUID
       ├─ leases each reserved RX queue to queue 1 on the existing netkit peer
       └─ configures separate SR-IOV and dummy devices in the Pod namespace

RX queue flow steering (StateDB)
  ├─ resolves each allocation's selector using verified CNI attachment
  │  addresses and the Pod's named ports, then writes
  │  networkdriver-rx-queue-flows
  └─ the flow reconciler programs matching physical-NIC rules

UnprepareResourceClaims (kubelet → DRA plugin)
  └─ finds allocations by ClaimUID
       └─ calls Device.Free with Config, ShareID, and ConsumedCapacity
            ├─ success → deletes the DRAAllocation
            └─ failure → retains the row for a later retry

ResourceSlice publication (a change to either table wakes this loop)
  ├─ networkdriver-dra-devices
  │    └─ supplies the current device, attributes, capacity, and whether it
  │       allows multiple allocations
  ├─ networkdriver-dra-allocations
  │    └─ pins every prepared allocation of a device to its recorded
  │       LogicalPool attribute
  └─ buildPoolsFromTable()
       ├─ groups all of the node's devices into one ResourceSlice pool,
       │  named after the node (stable regardless of device count)
       ├─ deviceSlices() splits that pool into multiple resourceslice.Slice
       │  batches once device count exceeds maxDevicesPerResourceSlice — the
       │  pool name itself never changes, only how many Slices make it up
       └─ draPlugin.PublishResources()

Agent restart
  ├─ local pods
  │    └─ resolve direct or template-generated ResourceClaims
  │         └─ ResourceClaim.Status.Devices
  │              ├─ restores ShareID from AllocatedDeviceStatus
  │              ├─ DeviceManager.RestoreDevice deserializes PreparedDevice
  │              └─ restores Config, LogicalPool, and ConsumedCapacity from
  │                 serialized data
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

`DeviceManager.RestoreDevice` reconstructs the device object from the durable
status; it does not re-create missing kernel state. If a node reboot removes an
on-demand link, `RunPodSandbox` calls `Device.Recover` when the replacement
sandbox starts. Recovery updates `PreparedDevice` in StateDB but not the
`ResourceClaim` status, so the device manager must return the same logical
allocation.

RX queue recovery restores the reservation. A replacement sandbox gets a new
lease when it starts, and the flow reconciler uses that attachment's verified
addresses.

Changes to either table trigger a new `ResourceSlice` publication. Every node
publishes exactly one `ResourceSlice` pool, named after the node. The DRA pool
name is independent from the user-configured logical pool and does not change
when the device count crosses the per-slice cap (see
`deviceSlices`/`maxDevicesPerResourceSlice`). If one shareable device has
several allocation rows in the same logical pool, publication keeps the parent
device in that pool. If its rows name different logical pools, the state is
ambiguous. The driver logs the conflict and does not advertise that device.

### Workload device metadata

The DRA plugin returns metadata for every prepared device. The Kubernetes DRA
helper writes that metadata to a versioned JSON stream and generates a CDI
specification that mounts the file read-only into each container that uses the
claim. Metadata contains the prepared device attributes, its pool and device
manager, and `networkData.interfaceName` with the final name inside the pod.
For an RX queue allocation, `rxQueueID` identifies the leased queue on that
interface. This is the virtual queue ID visible through the netkit device, not
the physical NIC queue ID.

A directly referenced `ResourceClaim` appears at:

```text
/var/run/kubernetes.io/dra-device-attributes/resourceclaims/<claimName>/<requestName>/networkdriver.cilium.io-metadata.json
```

A claim generated from a `ResourceClaimTemplate` appears at:

```text
/var/run/kubernetes.io/dra-device-attributes/resourceclaimtemplates/<podClaimName>/<requestName>/networkdriver.cilium.io-metadata.json
```

`podClaimName` is the name used under `pod.spec.resourceClaims`, not the
generated `ResourceClaim` name. The file contains the newest supported
metadata API version first, followed by older supported versions.

### Inspecting state at runtime

```bash
kubectl -n kube-system exec <cilium-pod> -c cilium-agent -- \
  cilium-dbg statedb |
  jq '{
    inventory: .["networkdriver-dra-devices"] | map({Name, Manager}),
    allocations: .["networkdriver-dra-allocations"] |
      map({DeviceName, Manager, LogicalPool, ShareID, ConsumedCapacity,
           PodUID, ClaimUID, Config})
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
      "LogicalPool": "sriov-pool",
      "ShareID": "",
      "ConsumedCapacity": null,
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

A shareable device may have several rows with the same `DeviceName` and
`LogicalPool`. Distinct `ShareID` values key those rows; each row records its
consumed capacity, claim UID, and prepared device.
For an RX queue allocation, `PreparedDevice` records the physical and virtual
queue IDs, the share ID, and the target Pod interface name.

## How to use the Network Driver

### 1. Enable the feature

The DRA framework, NRI (CRI integration hook), and device discovery require
host mounts that are not needed by any other Cilium feature. The Network
Driver must therefore be explicitly enabled:

```bash
helm upgrade cilium cilium/cilium \
  --set networkDriver.enabled=true
```

This sets `--enable-network-driver` on the agent.

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

**RX queue example — reserve 4 queues on ens1f0:**

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name: worker-node-1
spec:
  deviceManagerConfigs:
    rxQueue:
      enabled: true
      ifaces:
        - ifName: ens1f0
          count: 4
  pools:
    - name: rx-queue-pool
      filter:
        deviceManagers:
          - rxQueue
        ifNames:
          - ens1f0
```

`ens1f0` must be up and have at least five active RX queues. This configuration
publishes one DRA device named `ens1f0` with four units of `rxQueues` capacity.

#### Pool filters

Pools group devices that share a common purpose. Only devices matched by
the pool's filter get the pool name set on their `pool` device attribute —
used for `DeviceClass` CEL selector matching. This logical pool is
independent from the DRA `ResourceSlice` pool (`spec.pool.name`), which is
always the node name — see
[Allocation lifecycle](#allocation-lifecycle) above.
All specified filter fields are ANDed together.

| Filter field     | SR-IOV                                                                                  | Dummy                                   | RX queue                                |
|------------------|-------------------------------------------------------------------------------------------|------------------------------------------|-----------------------------------------|
| `deviceManagers` | Match when set to `sr-iov`                                                                | Match when set to `dummy`               | Match when set to `rxQueue`             |
| `ifNames`        | Kernel interface name of the VF (empty for DPDK/vfio-bound VFs, which have no kernel netdev; for a VF currently inside a pod netns, the last-known kernel ifname is preserved via `Merge` rather than cleared — use `pciAddrs` if you need a filter unaffected by this) | Kernel interface name of the dummy link | Physical interface name                 |
| `pfNames`        | Physical Function kernel interface name                                                   | Ignored — dummy devices always match    | Not applicable (non-empty → no match)   |
| `parentIfNames`  | Ignored — devices always match regardless of this filter                                  | Not applicable (non-empty → no match)   | Not applicable (non-empty → no match)   |
| `pciAddrs`       | PCI address of the VF (e.g. `0000:03:00.1`)                                               | Not applicable (non-empty → no match)   | Not applicable (non-empty → no match)   |
| `vendorIDs`      | PCI vendor ID                                                                              | Not applicable (non-empty → no match)   | Not applicable (non-empty → no match)   |
| `deviceIDs`      | PCI device ID                                                                              | Not applicable (non-empty → no match)   | Not applicable (non-empty → no match)   |
| `drivers`        | Kernel driver bound to the VF (e.g. `mlx5_core`, `vfio-pci`)                              | Not applicable (non-empty → no match)   | Not applicable (non-empty → no match)   |

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
   device, the recorded `LogicalPool` is kept for as long as that allocation
   exists, regardless of how filters re-evaluate in the meantime. If multiple
   rows name different logical pools, the driver logs the conflict and does
   not advertise the device. Pool pinning does **not** apply after the final
   allocation row is removed.
2. **Alphabetically first matching pool** — deterministic tie-break, applied
   fresh on every publish for a device with no prepared allocation.

An error is logged whenever a device matches more than one pool.

#### Device configuration options

Device-specific configuration is passed as opaque parameters in the
`ResourceClaim` (see step 3). Supported fields (from `types/types.go`):

| Field       | Type     | Description                                                                    |
|-------------|----------|--------------------------------------------------------------------------------|
| `vlan`      | `int32`  | 802.1q VLAN ID to configure on the device (SR-IOV only)                        |
| `podIfName` | `string` | Target Pod interface. RX queues use the existing interface and default to `eth0` |
| `rxQueue`   | `object` | Pod endpoint whose traffic is steered to the allocated RX queue                |
| `interfaceSysctlIPv4` | `map[string]string` | Leaf sysctl parameters (e.g. `arp_filter`) applied under `net.ipv4.conf.<interface>.` for the allocated interface, once it is up in the pod netns |
| `interfaceSysctlIPv6` | `map[string]string` | Same as above, under `net.ipv6.conf.<interface>.`                    |

`rxQueue.podEndpoint` selects a port on the Pod consuming the claim. Its `port`
may be a decimal number or a named container port; `protocol` is `TCP` or `UDP`.
It steers ingress traffic sent directly to the Pod's IPv4 and IPv6 addresses.
Currently, traffic must reach the physical NIC addressed to the Pod IP and
selected port, not a Service VIP.

Cilium does not support RX queue steering by VLAN ID or destination MAC
address. Rules match only destination IP, protocol and port.

The selected NIC must not carry another network whose addresses overlap
the Pod address space, including VLAN or macvlan networks. Without VLAN
or MAC filtering, matching traffic from those networks could enter the
Pod's leased queue.

If the Pod endpoint cannot be resolved, or two allocations select the same
tuple on one NIC, the flow row reports `Unresolved`. No rules are installed
for that allocation. The controller continues to check the configuration
after startup, while the Pod and queue allocation remain in place.

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

This example requests a dedicated SR-IOV Virtual Function. A device manager
that publishes consumable capacity also defines the qualified capacity names
that applications request under `exactly.capacity.requests`. Kubernetes
selects the device, assigns a share ID, and records the capacity consumed by
the claim. The network driver receives those values during preparation and
passes them to the selected device manager.

For example, the RX queue manager publishes `rxQueues` capacity. The following
class selects RX queue devices from `rx-queue-pool`:

```yaml
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: cilium-rx-queue
spec:
  selectors:
    - cel:
        expression: >-
          device.driver == "networkdriver.cilium.io" &&
          device.attributes["networkdriver.cilium.io"].deviceManager == "rxQueue" &&
          device.attributes["networkdriver.cilium.io"].pool == "rx-queue-pool"
```

This template requests one queue for the Pod's existing `eth0` interface and
steers TCP destination port 9000 for the Pod's IPv4 and IPv6 addresses to that
queue:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: rx-queue-claim
spec:
  spec:
    devices:
      requests:
        - name: rx-queue
          exactly:
            deviceClassName: cilium-rx-queue
            allocationMode: ExactCount
            count: 1
            capacity:
              requests:
                rxQueues: "1"
      config:
        - requests:
            - rx-queue
          opaque:
            driver: networkdriver.cilium.io
            parameters:
              podIfName: eth0
              rxQueue:
                podEndpoint:
                  port: "9000"
                  protocol: TCP
```

### 4. Request a device from a pod

Reference the `ResourceClaimTemplate` in the pod spec. This Pod requests the
SR-IOV claim from the first example:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: dpdk-app
spec:
  resourceClaims:
    - name: net
      resourceClaimTemplateName: sriov-claim
  containers:
    - name: app
      image: my-dpdk-app:latest
      resources:
        claims:
          - name: net
```

The RX queue template can be requested independently:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: rx-queue-app
spec:
  resourceClaims:
    - name: rx-queue
      resourceClaimTemplateName: rx-queue-claim
  containers:
    - name: app
      image: my-rx-queue-app:latest
      resources:
        claims:
          - name: rx-queue
```

A container must list the claim under `resources.claims` to use it. This tells
the container runtime to apply the CDI specification generated for the
allocation, including the read-only device metadata mount.

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
NAME                                              NODE           DRIVER                    POOL          AGE
worker-node-1-networkdriver.cilium.io-abc12   worker-node-1  networkdriver.cilium.io   worker-node-1   30s
```

The `POOL` column is always the node name — it is the DRA ResourceSlice
pool identity, independent of any logical pool configured under
`spec.pools`. If a node publishes more devices than fit in a single
`ResourceSlice`, `kubectl get resourceslice` shows multiple objects sharing
that same `POOL` value (see `maxDevicesPerResourceSlice`).

### Verify ResourceClaims and allocations

```bash
# List all resource claims
kubectl get resourceclaims -A

# Check claim status (allocated, reserved, device status)
kubectl get resourceclaim <name> -n <namespace> -o yaml

# Show the device, share ID, and consumed capacity selected for each request
kubectl get resourceclaim <name> -n <namespace> -o json | \
  jq '.status.allocation.devices.results[] |
      {device, shareID, consumedCapacity}'

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

### Verify an RX queue allocation

```bash
# Show the physical and virtual queue IDs and the target interface
kubectl -n kube-system exec <cilium-pod> -c cilium-agent -- \
  cilium-dbg statedb |
  jq '.["networkdriver-dra-allocations"][] |
      select(.Manager == "rxQueue") |
      {DeviceName, ShareID, ConsumedCapacity, PreparedDevice}'

# Show the steered flows, or why the selector does not resolve
kubectl -n kube-system exec <cilium-pod> -c cilium-agent -- \
  cilium-dbg statedb |
  jq '.["networkdriver-rx-queue-flows"]'

# On the node, confirm that RSS skips the reserved queues, that header/data
# splitting is on, and that the flow-steering rules target the leased queue
ethtool -x <nic>
ethtool -g <nic>
ethtool -n <nic>

# Confirm that the existing Pod interface is a two-queue netkit peer
kubectl exec rx-queue-app -- ip -details link show dev eth0

# Inspect the allocation metadata mounted through CDI
kubectl exec rx-queue-app -- \
  cat /var/run/kubernetes.io/dra-device-attributes/resourceclaimtemplates/\
rx-queue/rx-queue/networkdriver.cilium.io-metadata.json
```

The metadata file is a concatenated JSON stream with one object per supported
metadata API version. Look for `networkData.interfaceName` set to `eth0` and
the `rxQueueID` device attribute set to `1`.

## Feature status

Experimental. The API and configuration format may change between releases.
