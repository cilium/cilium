# Macvlan Device Manager

## Overview

The macvlan device manager creates and manages macvlan sub-interfaces on behalf of the Cilium Network Driver, following the same pattern as the SR-IOV and dummy device managers. It allows users to specify one or more parent interfaces and the number of macvlan sub-interfaces to create on each.

## Features

- **Multiple Parent Interfaces**: Configure macvlan sub-interfaces on multiple parent interfaces
- **Configurable Count**: Specify the number of sub-interfaces to create per parent interface
- **Macvlan Modes**: Support for all macvlan modes (private, vepa, bridge, passthru, source)
- **Automatic Interface Naming**: Sub-interfaces are named as `<parent>.<index>` (e.g., `eth0.0`, `eth0.1`)
- **Device Discovery**: Automatically discovers and lists existing macvlan interfaces
- **Resource Attributes**: Exposes parent interface name, MAC address, MTU, and macvlan mode as device attributes

## Configuration

Macvlan is configured via the `deviceManagerConfigs.macvlan` section of a
`CiliumNetworkDriverNodeConfig` (per-node) or `CiliumNetworkDriverClusterConfig`
(cluster-wide, distributed to matched nodes by the operator).

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
        - parentIfName: eth0     # Parent interface name
          count: 10              # Number of sub-interfaces to create
          mode: bridge           # Macvlan mode (optional, default: bridge)
  pools:
    - name: macvlan-pool
      filter:
        parentIfNames:
          - eth0
```

### Configuration Fields

**MacvlanDeviceManagerConfig:**
- `enabled` (bool): Enable/disable the macvlan device manager
- `ifaces` ([]MacvlanDeviceConfig): List of parent interfaces to configure

**MacvlanDeviceConfig:**
- `parentIfName` (string, required): Name of the parent interface
- `count` (int): Number of macvlan sub-interfaces to create
- `mode` (string, optional): Macvlan mode — one of:
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

### Filtering

Macvlan devices can be filtered using the following `CiliumNetworkDriverDeviceFilter` fields:

| Filter field     | Matches on                                                                                     |
|------------------|-----------------------------------------------------------------------------------------------|
| `deviceManagers` | Match when set to `macvlan`                                                                   |
| `ifNames`        | Device name with dots replaced by dashes (e.g. `eth0.0` → `eth0-0`; either form accepted)    |
| `parentIfNames`  | Parent interface kernel name (the interface the macvlan is attached to)                       |

The fields `pfNames`, `pciAddrs`, `vendorIDs`, `deviceIDs`, and `drivers` are not applicable
to macvlan devices — a filter specifying any of those fields will never match a macvlan device.

## Future Enhancements

Potential improvements:
1. **VLAN support**: Add VLAN tagging to macvlan interfaces
2. **MTU configuration**: Allow MTU override per sub-interface
3. **Source filtering**: Implement source mode with MAC filtering
4. **Statistics**: Expose interface statistics as metrics

## References

- Linux macvlan documentation: https://www.kernel.org/doc/Documentation/networking/macvlan.txt
- netlink library: https://github.com/vishvananda/netlink
- Kubernetes DRA: https://kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/
