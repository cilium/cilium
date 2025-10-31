# Description

This feature is an implementation of this CFP - https://github.com/cilium/design-cfps/blob/main/cilium/CFP-32810-hybrid-routing-mode.md .

# Datapath changes

Commit  - https://github.com/cilium/cilium/commit/4d99a9e5a50a5c89952677067b96419ab91b3baf

## Key Changes

### **New Subnet Map Infrastructure**
- Added `bpf/lib/subnet.h` with a new LPM trie-based subnet map (`cilium_subnet_map`)
- Implemented IPv4 and IPv6 subnet lookup functions with cluster ID support
- Map stores subnet prefix → identity mappings for efficient subnet identification

### **Enhanced Tunnel Skip Logic**
- **Host datapath** (`bpf_host.c`): Extended tunnel skip conditions to include same-subnet detection
- **Container datapath** (`bpf_lxc.c`): Modified packet handling to skip tunneling for intra-subnet traffic
- Logic: Skip tunneling if `(existing_skip_tunnel_flag || same_subnet_detected)`

### **Debug**
- Added new debug message types:
  - `DBG_SUBNET_CHECK`: Logs subnet comparison results
  - `DBG_TUNNEL_TRACE`: Traces subnet ID resolution
- Enhanced monitoring support in `pkg/monitor/datapath_debug.go` for troubleshooting

# Userspace changes

Commits:
- https://github.com/anubhabMajumdar/cilium/commit/a9b1c0dc64316e1bf0588785f6052240a0369397
- https://github.com/anubhabMajumdar/cilium/commit/508c64e2fac6df9a45809ad92510fd7173105923
- https://github.com/anubhabMajumdar/cilium/commit/a1845f182ba6ab73f4c2a1701c3cc26c753aa072

## Key Components Added

### **Core Infrastructure**
- **Hive Cell Integration**: Added `pkg/subnettopology/cell.go` with dependency injection setup
- **Dynamic Manager**: Implemented `dynamic_manager.go` for lifecycle management and configuration synchronization
- **File Watcher**: Created `watcher.go` for monitoring configuration file changes with MD5-based change detection
- **Daemon Integration**: Registered subnet topology cell in `daemon/cmd/cells.go`

### **eBPF Map Management**
- **Map Abstraction**: Added `map.go` with comprehensive eBPF map management
- **Key/Value Structures**: Implemented LPM trie-compatible data structures for subnet lookups
- **IPv4/IPv6 Support**: Map can store both IPv4 and IPv6 keys

# YAML file changes

- **New Routing Mode**: Added `hybrid` as a supported routing mode option in `values.yaml`
- **Subnet Topology Path**: Added `subnetTopologyFilePath` configuration (`/var/lib/cilium/subnet/subnet-topology`)
- **ConfigMap Integration**: Added `subnetTopologyConfigmapName` for subnet topology configuration 
- **Conditional Volume Mount**: Added subnet topology file mount when `routingMode` is `hybrid in `cilium-agent/daemonset.yaml`

# Testing done

## Single Cluster Testing

### Test Environment Setup

The testing was conducted on a single Azure Kubernetes Service (AKS) cluster with the following network topology:
- **Cloud Provider**: Microsoft Azure
- **Cluster Type**: AKS (Azure Kubernetes Service)
- **Network Configuration**: Pod and Node subnets deployed within the same Azure Virtual Network (VNET)
- **Subnet Architecture**: Separate subnets for pods and nodes, both residing in a single VNET to enable native routing capabilities

### Cilium Installation and Configuration

Cilium was deployed using a custom-built image containing the hybrid routing implementation. The installation command below shows the specific configuration parameters used:

```bash
cilium install -n kube-system cilium cilium/cilium --version v1.18.0 \
    --set azure.resourceGroup="<RESOURCE-GROUP>" \
    --set aksbyocni.enabled=false \
    --set nodeinit.enabled=false \
    --set hubble.enabled=true \
    --set envoy.enabled=false \
    --set cluster.id="<ID>" \
    --set cluster.name="<NAME>" \
    --set ipam.mode=delegated-plugin \
    --set routingMode=hybrid
    --set endpointRoutes.enabled=true \
    --set enable-ipv4=true \
    --set enableIPv4Masquerade=false \
    --set kubeProxyReplacement=true \
    --set kubeProxyReplacementHealthzBindAddr='0.0.0.0:<PORT>' \
    --set extraArgs="{--local-router-ipv4=<IP>} {--install-iptables-rules=true}" \
    --set endpointHealthChecking.enabled=false \
    --set cni.exclusive=false \
    --set bpf.enableTCX=false \
    --set bpf.hostLegacyRouting=true \
    --set l7Proxy=false \
    --set sessionAffinity=true \
    --set "extraVolumes[0].name=subnet-topology-file" \
    --set "extraVolumes[0].configMap.name=subnet-topology" \
    --set "extraVolumes[0].configMap.optional=true" \
    --set "extraVolumeMounts[0].name=subnet-topology-file" \
    --set "extraVolumeMounts[0].mountPath=/var/lib/cilium/subnet" \
    --set "extraVolumeMounts[0].readOnly=true" \
    --set subnetTopologyFilePath="/var/lib/cilium/subnet/subnet-topology" \
    --set "extraConfig.subnet-topology-file-path"="/var/lib/cilium/subnet/subnet-topology"
```

**Key Configuration Highlights**:
- `routingMode=hybrid`: To enable hybrid routing
- `ipam.mode=delegated-plugin`: Uses Azure CNI for IP address management
- `hubble.enabled=true`: Enables network flow observability for testing verification
- `bpf.hostLegacyRouting=true`: Enables legacy routing mode for compatibility with Azure networking

**Subnet topology configmap**

```
apiVersion: v1
data:
  subnet-topology: 10.1.1.0/24
kind: ConfigMap
metadata:
  name: subnet-topology
  namespace: kube-system
```

#### Hybrid Routing Activation and Testing

**Steps Performed**:
1. **Subnet Topology Configuration**: Applied the `subnet-topology` ConfigMap containing the subnet-to-identity mappings
2. **eBPF Map Synchronization**: Waited for the eBPF LPM trie map to synchronize with the new subnet topology data
3. **Flow Behavior Verification**: Monitored Hubble flows to observe the routing behavior changes
4. **Debug Verification**: Used custom debug messages (`DBG_SUBNET_CHECK` and `DBG_TUNNEL_TRACE`) to verify internal decision-making logic

**Results**:
- ✅ Hybrid routing activated successfully
- **Hubble Flow Observations**: Inter-node traffic within the same subnet began showing `to-stack/network` flows (native routing)
- **Behavior Validation**: Traffic between pods in the same subnet bypassed tunneling and used direct Azure VNET routing
- **Debug Log Verification**: Custom debug messages confirmed:
  - Subnet identity lookups were functioning correctly
  - Same-subnet detection logic was working as expected
  - Tunnel bypass decisions were being made appropriately

#### Dynamic Configuration Testing

**Steps Performed**:
1. **Configuration Removal**: Deleted the `subnet-topology` ConfigMap
2. **eBPF Map Cleanup**: Waited for the eBPF map to synchronize and clear subnet topology data
3. **Behavior Reverification**: Monitored traffic flows to confirm fallback to tunnel mode

**Results**:
- ✅ Dynamic configuration changes worked as expected
- **Hubble Flow Observations**: After ConfigMap deletion, inter-node traffic reverted to showing `to-overlay` flows
- **Behavior Validation**: System correctly fell back to full tunnel mode when subnet topology information was unavailable
- **No Service Disruption**: All connectivity remained functional throughout the configuration changes

## Multi-Cluster Testing (Cluster Mesh)

### Test Environment Setup

**Cluster Architecture**:
- **Primary Cluster**: Single AKS cluster configured as described above
- **Secondary Cluster**: Identical AKS cluster configuration in a separate resource group
- **Network Connectivity**: Azure VNET peering established between the two cluster VNETs to enable cross-cluster communication
- **Service Mesh**: Cilium Cluster Mesh enabled to provide cross-cluster service discovery and load balancing

### Cluster Mesh Configuration

**Steps Performed**:
1. **Cluster Mesh Enablement**: Followed the official Cilium documentation for [Cluster Mesh setup](https://docs.cilium.io/en/stable/network/clustermesh/clustermesh/)
2. **Cluster Connection**: Connected both clusters using the Cilium Cluster Mesh connectivity protocols
3. **Status Verification**: Confirmed successful setup using `cilium clustermesh status` command, which reported "OK" status
4. **Service Configuration**: Deployed the cross-cluster service example from the [official documentation](https://docs.cilium.io/en/stable/network/clustermesh/services/)
5. **Subnet Topology Application**: Applied the `subnet-topology` ConfigMap to both clusters to enable hybrid routing across the mesh

The following diagram illustrates how hybrid routing operates with this change in a multi-cluster environment:

<img width="11650" height="9470" alt="hybrid-routing-diagram" src="https://github.com/user-attachments/assets/12a53efa-c037-47ec-870f-ab456124a06e" />

#### Scenario 1: Cross-Cluster Communication with Same Subnet Topology

**Configuration**: Both clusters configured with identical subnet topologies, simulating pods in the same logical subnet across clusters.

**Observations**:
- ✅ **Hubble Flows**: Show `to-stack/network` flows for cross-cluster communication
- ✅ **Debug Logs**: Confirm same-subnet detection and tunnel bypass logic activation

#### Scenario 2: Cross-Cluster Communication with Different Subnet Topology

**Configuration**: Clusters configured with different subnet topologies, simulating pods in different logical subnets across clusters.

**Observations**:
- ✅ **Hubble Flows**: Show `to-overlay` flows for cross-cluster communication
- ✅ **Debug Logs**: Confirm different-subnet detection and tunnel encapsulation activation

#### Scenario 3: Cross-Cluster Communication with Pod Subnet and Overlay Cilium clusters

**Configuration**: An Overlay cluster was added to setup in Scenario 1.

**Observations**:
- ✅ **Hubble Flows**: Show `to-overlay` flows for cross-cluster communication
- ✅ **Debug Logs**: Confirm same as well as different-subnet detection and tunnel encapsulation activation

[8_21_2025, 8_44_11 PM - Screen - Video Project 7.webm](https://github.com/user-attachments/assets/182f7404-1d52-4929-b61e-4f4fbbc8cad5)

# Notes

- Haven't implemented atomic read of the subnet map while making routing decision yet
- Will remove the debug traces from data path before merging the PR
- Missing unit tests, will add after I get some initial feedback
- Will revert back to runnel mode as default routing option in `values.yaml`
- Marking PR as draft. This PR will provide an overview of exactly what I am trying to achieve. Given its size and complexity, I will break it up into pieces for easier review and merging.

Please ensure your pull request adheres to the following guidelines:

- [x] For first time contributors, read [Submitting a pull request](https://docs.cilium.io/en/stable/contributing/development/contributing_guide/#submitting-a-pull-request)
- [ ] All code is covered by unit and/or runtime tests where feasible.
- [x] All commits contain a well written commit description including a title,
      description and a `Fixes: #XXX` line if the commit addresses a particular
      GitHub issue.
- [ ] If your commit description contains a `Fixes: <commit-id>` tag, then
      please add the commit author[s] as reviewer[s] to this issue.
- [x] All commits are signed off. See the section [Developer’s Certificate of Origin](https://docs.cilium.io/en/stable/contributing/development/contributing_guide/#dev-coo)
- [ ] Provide a title or release-note blurb suitable for the release notes.
- [ ] Are you a user of Cilium? Please add yourself to the [Users doc](https://github.com/cilium/cilium/blob/main/USERS.md)
- [ ] Thanks for contributing!

<!-- Description of change -->

Fixes: #issue-number

```release-note
<!-- Enter the release note text here if needed or remove this section! -->
```
