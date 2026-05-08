# Cilium Network Driver

Cilium Network Driver allows cilium-agent to expose network devices directly
to pods, without those pods participating in the Cilium fabric. The driver
registers as a
[DRA](https://kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/)
plugin and publishes `ResourceSlice` resources to the Kubernetes API so pods
can claim devices via the standard DRA framework.

## Requirements

- Kubernetes v1.34+
- Cilium operator and agent with `--enable-cilium-network-driver` (set automatically
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
Available device managers:

| Manager  | Key in CRD        | Devices managed                        |
|----------|-------------------|----------------------------------------|
| `sriov`  | `sriov`           | SR-IOV Virtual Functions (legacy VFs)  |
| `dummy`  | `dummy`           | Linux dummy interfaces                 |
| `macvlan`| `macvlan`         | Macvlan sub-interfaces                 |

## How to use the Network Driver

### 1. Enable the feature

The DRA framework, NRI (CRI integration hook), and device discovery require
host mounts that are not needed by any other Cilium feature. The Network
Driver must therefore be explicitly enabled:

```bash
helm upgrade cilium cilium/cilium \
  --set networkDriver.enabled=true
```

This sets `--enable-cilium-network-driver` on both the agent and operator.

### 2. Provide a node configuration

The agent reads its configuration from a `CiliumNetworkDriverNodeConfig` CRD
whose `metadata.name` matches the node hostname. The operator can generate
these automatically from a cluster-wide `CiliumNetworkDriverClusterConfig`
(see section below), or you can create them manually.

**Minimal example — dummy devices:**

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name: worker-node-1        # must match node hostname
spec:
  driverName: "networkdriver.cilium.io"
  deviceManagerConfigs:
    dummy:
      enabled: true
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
  driverName: "networkdriver.cilium.k8s.io"
  deviceManagerConfigs:
    sriov:
      enabled: true
      ifaces:
        - ifName: ens1f0
          vfCount: 4
  pools:
    - name: sriov-pool
      filter:
        pfNames:
          - ens1f0
```

**Macvlan example — 8 sub-interfaces on eth0:**

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name: worker-node-1
spec:
  driverName: "networkdriver.cilium.io"
  deviceManagerConfigs:
    macvlan:
      enabled: true
      ifaces:
        - parentIfName: eth0
          count: 8
          mode: bridge    # private | vepa | bridge | passthru | source
  pools:
    - name: macvlan-pool
      filter:
        parentIfNames:
          - eth0
```

#### Pool filters

Pools group devices that share a common purpose. Only devices matched by
the pool's filter are advertised in the corresponding `ResourceSlice`.
All specified filter fields are ANDed together.

| Filter field      | Matches on                                          |
|-------------------|-----------------------------------------------------|
| `ifNames`         | Exact device interface name                         |
| `pfNames`         | SR-IOV Physical Function kernel ifname              |
| `pciAddrs`        | PCI address (e.g. `0000:03:00.1`)                   |
| `vendorIDs`       | PCI vendor ID                                       |
| `deviceIDs`       | PCI device ID                                       |
| `drivers`         | Kernel driver bound to the device                   |
| `deviceManagers`  | Device manager type (`sr-iov`, `dummy`, `macvlan`)  |
| `parentIfNames`   | Macvlan parent interface kernel ifname              |

#### Device configuration options

Device-specific configuration is passed as opaque parameters in the
`ResourceClaim` (see step 4). Supported fields (from `types/types.go`):

| Field           | Type     | Description                                              |
|-----------------|----------|----------------------------------------------------------|
| `vlan`          | `uint16` | 802.1q VLAN ID to configure on the device                |
| `ipv4Addr`      | CIDR     | Static IPv4 address/prefix (e.g. `192.168.1.5/24`)      |
| `ipv6Addr`      | CIDR     | Static IPv6 address/prefix                               |
| `ipPool`        | `string` | `CiliumResourceIPPool` name for dynamic address allocation|
| `routes`        | list     | Static routes to add (destination + gateway)             |
| `podIfName`     | `string` | Rename the interface inside the pod namespace            |
| `networkConfig` | `string` | Reference to a `CiliumResourceNetworkConfig` resource    |

### 3. Cluster-wide configuration (operator)

Instead of creating per-node `CiliumNetworkDriverNodeConfig` resources
manually, the operator can distribute configuration to multiple nodes using a
`CiliumNetworkDriverClusterConfig`. The operator reconciles `CiliumNetworkDriverNodeConfig`
resources for each matched node.

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverClusterConfig
metadata:
  name: sriov-workers
spec:
  nodeSelector:
    matchLabels:
      feature.node.kubernetes.io/network-sriov.capable: "true"
  spec:
    driverName: "networkdriver.cilium.k8s.io"
    deviceManagerConfigs:
      sriov:
        enabled: true
        ifaces:
          - ifName: ens1f0
            vfCount: 4
    pools:
      - name: sriov-pool
        filter:
          pfNames:
            - ens1f0
```

If two `CiliumNetworkDriverClusterConfig` resources select the same node,
the **older** one (by `creationTimestamp`) takes precedence and the newer one
is marked with a `cilium.io/ConflictingClusterConfiguration` status condition.
Configurations that end up marked due to a conflict are not selected for any
nodes, even if there are nodes that would match it.

### 4. Prepare device requests

Create a `DeviceClass` to encapsulate device selection logic:

```yaml
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: sriov-pool.networkdriver.cilium.k8s.io
spec:
  selectors:
  - cel:
      expression: >
        device.driver == "networkdriver.cilium.k8s.io" &&
        device.attributes["networkdriver.cilium.k8s.io"].pool == "sriov-pool"
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
          deviceClassName: sriov-pool.networkdriver.cilium.k8s.io
      config:
      - requests:
          - net
        opaque:
          driver: networkdriver.cilium.k8s.io
          parameters:
            vlan: 1001
            ipv4Addr: 192.168.1.5/24
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
                device.driver == "networkdriver.cilium.k8s.io" &&
                device.attributes["networkdriver.cilium.k8s.io"].pool == "sriov-pool"
      config:
      - requests:
          - net
        opaque:
          driver: networkdriver.cilium.k8s.io
          parameters:
            vlan: 1001
            ipPool: my-pool
```

### 5. Request a device from a pod

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

### 6. IPAM — dynamic IP address allocation

The operator can manage IP pools for network driver devices using
`CiliumResourceIPPool`. Pools can be created manually or auto-created at
operator startup via the `--auto-create-cilium-resource-ip-pools` flag.

**Create a pool manually:**

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumResourceIPPool
metadata:
  name: my-pool
spec:
  ipv4:
    cidrs:
      - 192.168.100.0/24
    maskSize: 32
  ipv6:
    cidrs:
      - fd00::/120
    maskSize: 128
```

**Auto-create on operator startup (Helm / operator flag):**

```
--auto-create-cilium-resource-ip-pools=my-pool=ipv4-cidrs:192.168.100.0/24;ipv4-mask-size:32
```

Nodes request allocations by setting `spec.ipam.resourcePools` in their
`CiliumNode` resource. The operator allocates addresses and writes them back
to `CiliumNode.status`.

### 7. Shared network configuration (CiliumResourceNetworkConfig)

`CiliumResourceNetworkConfig` allows you to define reusable network
parameters (VLAN, IP pool, netmask, static routes) that are applied to
claimed devices. It can be scoped to a subset of nodes via `nodeSelector`.

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumResourceNetworkConfig
metadata:
  name: vlan-1001
spec:
  - nodeSelector:
      matchLabels:
        rack: "a"
    ipPool: my-pool
    vlan: 1001
    ipv4:
      netMask: 24
      staticRoutes:
        - destination: 10.0.0.0/8
          gateway: 192.168.100.1
  - nodeSelector:
      matchLabels:
        rack: "b"
    ipPool: my-pool-2
    vlan: 2002
    ipv4:
      netMask: 24
      staticRoutes:
        - destination: 10.0.0.0/8
          gateway: 192.168.200.1
```

A `CiliumResourceNetworkConfig` contains a list of specs, and the nodes matching
a certain entry will use the parameters defined when referencing a config by name.
This can be useful if nodes are connected to different underlying networks
with varying vlan IDs and address ranges.

Reference it from a `ResourceClaim` by setting `networkConfig: vlan-1001`
in the opaque parameters.

## Verifying the setup

### Check node configuration was applied

```bash
# List all per-node configurations
kubectl get ciliumnetworkdrivernodeconfigs

# Inspect the configuration for a specific node
kubectl get ciliumnetworkdrivernodeconfig worker-node-1 -o yaml
```

### Check cluster-wide configurations

```bash
kubectl get ciliumnetworkdriverclusterconfigs

# Check for conflicts
kubectl get ciliumnetworkdriverclusterconfig my-config -o jsonpath='{.status.conditions}'
```

### Verify published devices (ResourceSlices)

```bash
# List all ResourceSlices published by the network driver
# note: the `driver=` parameter should match the driver name
# from CiliumNetworkDriverNodeConfig
kubectl get resourceslice -l resource.kubernetes.io/driver=networkdriver.cilium.io

# Or for a another DRA driver
kubectl get resourceslice -l resource.kubernetes.io/driver=<name>

# Or for all DRA drivers
kubectl get resourceslice

# Inspect a specific slice
kubectl get resourceslice <name> -o yaml
```

Example output:
```
NAME                                        NODE           DRIVER                      POOL         AGE
worker-node-1-sriov.cilium.k8s.io-abc12    worker-node-1  sriov.cilium.k8s.io         sriov-pool   30s
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

### Verify IP pools (IPAM)

```bash
# List IP pools
kubectl get ciliumresourceippools
kubectl get crip       # short name

# Inspect a pool
kubectl get ciliumresourceippool my-pool -o yaml

# Check per-node IP allocations in CiliumNode
kubectl get ciliumnode worker-node-1 -o jsonpath='{.spec.ipam.resourcePools}'
```

### Verify DeviceClasses

```bash
kubectl get deviceclasses
```

## Sysdump

The following resources are automatically collected by `cilium sysdump`:

| Collected resource                    | File in sysdump                              |
|---------------------------------------|----------------------------------------------|
| `CiliumNetworkDriverNodeConfig`       | `network-driver-nodeconfigs.yaml`            |
| `CiliumNetworkDriverClusterConfig`    | `network-driver-clusterconfigs.yaml`         |
| `ResourceSlice`                       | `network-driver-resourceslices.yaml`         |
| `DeviceClass`                         | `network-driver-deviceclasses.yaml`          |
| `ResourceClaim`                       | `network-driver-resourceclaims.yaml`         |
| `ResourceClaimTemplate`               | `network-driver-resourceclaimTemplates.yaml` |

> **Note:** `CiliumResourceIPPool` is not yet collected by sysdump. Collect
> it manually:
> ```bash
> kubectl get ciliumresourceippools -o yaml
> ```

## Feature status

Experimental. The API and configuration format may change between releases.
