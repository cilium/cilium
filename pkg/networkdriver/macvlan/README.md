# Macvlan Device Manager Implementation

## Overview

This implementation adds a macvlan device manager to the Cilium Network Driver, following the same pattern as the existing SR-IOV and dummy device managers. The macvlan device manager allows users to specify a parent interface and the number of macvlan sub-interfaces to create.

## Features

- **Multiple Parent Interfaces**: Configure macvlan sub-interfaces on multiple parent interfaces
- **Configurable Count**: Specify the number of sub-interfaces to create per parent interface
- **Macvlan Modes**: Support for all macvlan modes (private, vepa, bridge, passthru, source)
- **Automatic Interface Naming**: Sub-interfaces are named as `<parent>.<index>` (e.g., `eth0.0`, `eth0.1`)
- **Device Discovery**: Automatically discovers and lists existing macvlan interfaces
- **Resource Attributes**: Exposes parent interface name, MAC address, MTU, and macvlan mode as device attributes

## Architecture

### Files Added/Modified

1. **pkg/networkdriver/types/types.go**
   - Added `DeviceManagerTypeMacvlan` enum value
   - Added macvlan string constant
   - Updated String(), MarshalText(), and UnmarshalText() methods

2. **pkg/networkdriver/macvlan/macvlan.go** (NEW)
   - `MacvlanManager`: Main device manager implementation
   - `MacvlanDevice`: Device representation
   - Interface creation and management logic

3. **pkg/networkdriver/macvlan/macvlan_test.go** (NEW)
   - Comprehensive unit tests for device manager
   - Tests for device attributes, matching, serialization, and listing

4. **pkg/networkdriver/devicemanagers/managers.go**
   - Added macvlan manager initialization

5. **pkg/k8s/apis/cilium.io/v2alpha1/network_driver_types.go**
   - Added `MacvlanDeviceManagerConfig` type
   - Added `MacvlanDeviceConfig` type
   - Added macvlan field to `CiliumNetworkDriverDeviceManagerConfig`

6. **examples/networkdriver/macvlan-example.yaml** (NEW)
   - Example configuration showing how to use the macvlan device manager

## Configuration

### CRD Configuration

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriver
metadata:
  name: network-driver-config
spec:
  deviceManagers:
    macvlan:
      enabled: true
      ifaces:
        - parentIfName: eth0     # Parent interface name
          count: 10              # Number of sub-interfaces
          mode: bridge           # Macvlan mode (optional, default: bridge)
```

### Configuration Fields

**MacvlanDeviceManagerConfig:**
- `enabled` (bool): Enable/disable the macvlan device manager
- `ifaces` ([]MacvlanDeviceConfig): List of parent interfaces to configure

**MacvlanDeviceConfig:**
- `parentIfName` (string, required): Name of the parent interface
- `count` (int): Number of macvlan sub-interfaces to create
- `mode` (string, optional): Macvlan mode - one of:
  - `private`: No communication between macvlan devices
  - `vepa`: Virtual Ethernet Port Aggregator mode
  - `bridge`: All endpoints are directly connected (default)
  - `passthru`: Single macvlan device per parent
  - `source`: Source mode for specific use cases

## Macvlan Modes Explained

1. **Bridge Mode** (default): All endpoints on the same parent interface can communicate directly. This is the most common mode.

2. **Private Mode**: Macvlan devices on the same parent cannot communicate with each other, even if on the same VLAN.

3. **VEPA Mode**: All frames are transmitted to the external switch, even for local communication. Requires switch support.

4. **Passthru Mode**: Allows a single macvlan device to be connected to the parent interface. The macvlan device inherits the parent's MAC address.

5. **Source Mode**: Allows filtering based on a list of allowed source MAC addresses.

## Device Attributes

Each macvlan device exposes the following attributes in Kubernetes DRA:

- `ifName`: The interface name (e.g., "eth0.0")
- `kernelIfName`: The kernel interface name (same as ifName)
- `mac_address`: Hardware address of the device
- `mtu`: Maximum transmission unit
- `flags`: Interface flags (e.g., "up|broadcast|running")
- `parentIfName`: Name of the parent interface (e.g., "eth0")
- `macvlanMode`: Configured macvlan mode (e.g., "bridge")
- `deviceManager`: Always "macvlan"

## Usage Example

### 1. Configure the Device Manager

Apply the CiliumNetworkDriver configuration:

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriver
metadata:
  name: network-driver-config
spec:
  deviceManagers:
    macvlan:
      enabled: true
      ifaces:
        - parentIfName: eth0
          count: 10
          mode: bridge
```

This will create 10 macvlan sub-interfaces: `eth0.0`, `eth0.1`, ..., `eth0.9`

### 2. Create a ResourceClass

```yaml
apiVersion: resource.k8s.io/v1alpha3
kind: ResourceClass
metadata:
  name: macvlan-network
spec:
  driverName: network.cilium.io
  selectors:
    - cel:
        expression: device.attributes["deviceManager"].string == "macvlan"
```

### 3. Create a ResourceClaimTemplate

```yaml
apiVersion: resource.k8s.io/v1alpha3
kind: ResourceClaimTemplate
metadata:
  name: macvlan-claim
spec:
  spec:
    devices:
      requests:
        - name: network
          deviceClassName: macvlan-network
```

### 4. Use in a Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  resourceClaims:
    - name: network
      resourceClaimTemplateName: macvlan-claim
  containers:
    - name: test
      image: debian:bookworm
      command: ["sleep", "6000"]
      resources:
        claims:
          - name: network
```

## Implementation Details

### Interface Creation

The macvlan manager creates sub-interfaces during initialization:

1. Verifies parent interface exists
2. Creates macvlan link with specified mode
3. Brings the interface up
4. Logs success or errors

Interfaces are named as `<parent>.<index>` starting from 0.

### Device Discovery

The `ListDevices()` method:
1. Lists all network links
2. Filters for macvlan type
3. Skips down interfaces
4. Resolves parent interface name
5. Returns device list with full attributes

### Device Lifecycle

- **Setup**: Currently a no-op (interface already exists)
- **Free**: Currently a no-op (interface persists)
- **Restore**: Deserializes device from stored state

### Filtering

Devices can be filtered by:
- Device manager type (`deviceManager`)
- Interface name (`ifName`)
- Parent interface name (`parentIfName`)
- Macvlan mode (`macvlanMode`)

## Testing

Run the test suite:

```bash
go test -v ./pkg/networkdriver/macvlan/...
```

Tests cover:
- Device attribute retrieval
- Filter matching logic
- Binary serialization/deserialization
- Device manager type
- Device restoration
- Device listing with mocked netlink

## Comparison with Other Device Managers

| Feature | SR-IOV | Dummy | Macvlan |
|---------|--------|-------|---------|
| Hardware Support Required | Yes (SR-IOV NIC) | No | No |
| Sub-interface Creation | PCI VFs | Manual | Automatic |
| Configuration Complexity | High | Low | Medium |
| Performance | Highest | Lowest | Medium-High |
| Isolation | Hardware | None | Software |
| Use Case | Production workloads | Testing | Multi-tenant networks |

## Future Enhancements

Potential improvements:
1. **VLAN support**: Add VLAN tagging to macvlan interfaces
2. **IP configuration**: Pre-configure IP addresses on interfaces
3. **MTU configuration**: Allow MTU override per sub-interface
4. **Deletion support**: Clean up interfaces on pod deletion
5. **Source filtering**: Implement source mode with MAC filtering
6. **Statistics**: Expose interface statistics as metrics

## References

- Linux macvlan documentation: https://www.kernel.org/doc/Documentation/networking/macvlan.txt
- netlink library: https://github.com/vishvananda/netlink
- Kubernetes DRA: https://kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/
