# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [datapathplugins.proto](#datapathplugins-proto)
    - [AttachmentContext](#datapathplugins-AttachmentContext)
    - [AttachmentContext.Host](#datapathplugins-AttachmentContext-Host)
    - [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo)
    - [AttachmentContext.LXC](#datapathplugins-AttachmentContext-LXC)
    - [AttachmentContext.Network](#datapathplugins-AttachmentContext-Network)
    - [AttachmentContext.Overlay](#datapathplugins-AttachmentContext-Overlay)
    - [AttachmentContext.PodInfo](#datapathplugins-AttachmentContext-PodInfo)
    - [AttachmentContext.Socket](#datapathplugins-AttachmentContext-Socket)
    - [AttachmentContext.Wireguard](#datapathplugins-AttachmentContext-Wireguard)
    - [AttachmentContext.XDP](#datapathplugins-AttachmentContext-XDP)
    - [Config](#datapathplugins-Config)
    - [InstrumentCollectionRequest](#datapathplugins-InstrumentCollectionRequest)
    - [InstrumentCollectionRequest.Collection](#datapathplugins-InstrumentCollectionRequest-Collection)
    - [InstrumentCollectionRequest.Collection.Map](#datapathplugins-InstrumentCollectionRequest-Collection-Map)
    - [InstrumentCollectionRequest.Collection.MapsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-MapsEntry)
    - [InstrumentCollectionRequest.Collection.Program](#datapathplugins-InstrumentCollectionRequest-Collection-Program)
    - [InstrumentCollectionRequest.Collection.ProgramsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-ProgramsEntry)
    - [InstrumentCollectionRequest.Hook](#datapathplugins-InstrumentCollectionRequest-Hook)
    - [InstrumentCollectionRequest.Hook.AttachTarget](#datapathplugins-InstrumentCollectionRequest-Hook-AttachTarget)
    - [InstrumentCollectionResponse](#datapathplugins-InstrumentCollectionResponse)
    - [LocalNodeConfig](#datapathplugins-LocalNodeConfig)
    - [PrepareCollectionRequest](#datapathplugins-PrepareCollectionRequest)
    - [PrepareCollectionRequest.CollectionSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec)
    - [PrepareCollectionRequest.CollectionSpec.MapSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapSpec)
    - [PrepareCollectionRequest.CollectionSpec.MapsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapsEntry)
    - [PrepareCollectionRequest.CollectionSpec.ProgramSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramSpec)
    - [PrepareCollectionRequest.CollectionSpec.ProgramsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramsEntry)
    - [PrepareCollectionResponse](#datapathplugins-PrepareCollectionResponse)
    - [PrepareCollectionResponse.HookSpec](#datapathplugins-PrepareCollectionResponse-HookSpec)
    - [PrepareCollectionResponse.HookSpec.OrderingConstraint](#datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint)
  
    - [HookType](#datapathplugins-HookType)
    - [PrepareCollectionResponse.HookSpec.OrderingConstraint.Order](#datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint-Order)
  
    - [DatapathPlugin](#datapathplugins-DatapathPlugin)
  
- [host_config.proto](#host_config-proto)
    - [BPFHost](#datapathplugins-BPFHost)
  
- [lxc_config.proto](#lxc_config-proto)
    - [BPFLXC](#datapathplugins-BPFLXC)
  
- [node_config.proto](#node_config-proto)
    - [Node](#datapathplugins-Node)
  
- [overlay_config.proto](#overlay_config-proto)
    - [BPFOverlay](#datapathplugins-BPFOverlay)
  
- [sock_config.proto](#sock_config-proto)
    - [BPFSock](#datapathplugins-BPFSock)
  
- [wireguard_config.proto](#wireguard_config-proto)
    - [BPFWireguard](#datapathplugins-BPFWireguard)
  
- [xdp_config.proto](#xdp_config-proto)
    - [BPFXDP](#datapathplugins-BPFXDP)
  
- [Scalar Value Types](#scalar-value-types)



<a name="datapathplugins-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## datapathplugins.proto



<a name="datapathplugins-AttachmentContext"></a>

### AttachmentContext
AttachmentContext contains the context about the attachment point in
question. It may carry endpoint-specific information used to determine which
hooks to load or how to configure them.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| host | [AttachmentContext.Host](#datapathplugins-AttachmentContext-Host) |  |  |
| lxc | [AttachmentContext.LXC](#datapathplugins-AttachmentContext-LXC) |  |  |
| overlay | [AttachmentContext.Overlay](#datapathplugins-AttachmentContext-Overlay) |  |  |
| socket | [AttachmentContext.Socket](#datapathplugins-AttachmentContext-Socket) |  |  |
| wireguard | [AttachmentContext.Wireguard](#datapathplugins-AttachmentContext-Wireguard) |  |  |
| xdp | [AttachmentContext.XDP](#datapathplugins-AttachmentContext-XDP) |  |  |






<a name="datapathplugins-AttachmentContext-Host"></a>

### AttachmentContext.Host



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |






<a name="datapathplugins-AttachmentContext-InterfaceInfo"></a>

### AttachmentContext.InterfaceInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="datapathplugins-AttachmentContext-LXC"></a>

### AttachmentContext.LXC



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |
| pod_info | [AttachmentContext.PodInfo](#datapathplugins-AttachmentContext-PodInfo) |  |  |






<a name="datapathplugins-AttachmentContext-Network"></a>

### AttachmentContext.Network







<a name="datapathplugins-AttachmentContext-Overlay"></a>

### AttachmentContext.Overlay



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |






<a name="datapathplugins-AttachmentContext-PodInfo"></a>

### AttachmentContext.PodInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  |  |
| pod_name | [string](#string) |  |  |
| container_name | [string](#string) |  |  |






<a name="datapathplugins-AttachmentContext-Socket"></a>

### AttachmentContext.Socket







<a name="datapathplugins-AttachmentContext-Wireguard"></a>

### AttachmentContext.Wireguard



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |






<a name="datapathplugins-AttachmentContext-XDP"></a>

### AttachmentContext.XDP



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |






<a name="datapathplugins-Config"></a>

### Config



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| host | [BPFHost](#datapathplugins-BPFHost) |  |  |
| lxc | [BPFLXC](#datapathplugins-BPFLXC) |  |  |
| overlay | [BPFOverlay](#datapathplugins-BPFOverlay) |  |  |
| socket | [BPFSock](#datapathplugins-BPFSock) |  |  |
| wireguard | [BPFWireguard](#datapathplugins-BPFWireguard) |  |  |
| xdp | [BPFXDP](#datapathplugins-BPFXDP) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest"></a>

### InstrumentCollectionRequest
Phase 2: Cilium has constructed and loaded the collection along with any
dispatcher programs that are meant to replace existing entrypoints in the
collection. Cilium sends a round of requests to any plugins that wanted to
inject hooks.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| collection | [InstrumentCollectionRequest.Collection](#datapathplugins-InstrumentCollectionRequest-Collection) |  |  |
| local_node_config | [LocalNodeConfig](#datapathplugins-LocalNodeConfig) |  |  |
| attachment_context | [AttachmentContext](#datapathplugins-AttachmentContext) |  |  |
| config | [Config](#datapathplugins-Config) |  |  |
| hooks | [InstrumentCollectionRequest.Hook](#datapathplugins-InstrumentCollectionRequest-Hook) | repeated |  |
| pins | [string](#string) |  |  |
| cookie | [string](#string) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Collection"></a>

### InstrumentCollectionRequest.Collection
Program and map IDs in the collection


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| programs | [InstrumentCollectionRequest.Collection.ProgramsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-ProgramsEntry) | repeated |  |
| maps | [InstrumentCollectionRequest.Collection.MapsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-MapsEntry) | repeated |  |






<a name="datapathplugins-InstrumentCollectionRequest-Collection-Map"></a>

### InstrumentCollectionRequest.Collection.Map



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Collection-MapsEntry"></a>

### InstrumentCollectionRequest.Collection.MapsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [InstrumentCollectionRequest.Collection.Map](#datapathplugins-InstrumentCollectionRequest-Collection-Map) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Collection-Program"></a>

### InstrumentCollectionRequest.Collection.Program
Would contain information about programs and maps in this collection
such as names, IDs, etc. This could be consumed by plugin programs
themselves, e.g., for sharing map state.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Collection-ProgramsEntry"></a>

### InstrumentCollectionRequest.Collection.ProgramsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [InstrumentCollectionRequest.Collection.Program](#datapathplugins-InstrumentCollectionRequest-Collection-Program) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Hook"></a>

### InstrumentCollectionRequest.Hook



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [HookType](#datapathplugins-HookType) |  |  |
| target | [string](#string) |  |  |
| attach_target | [InstrumentCollectionRequest.Hook.AttachTarget](#datapathplugins-InstrumentCollectionRequest-Hook-AttachTarget) |  | Contains target metadata necessary for freplace program load. |
| pin_path | [string](#string) |  | The plugin must pin the program to this pin path before responding to Cilium. |






<a name="datapathplugins-InstrumentCollectionRequest-Hook-AttachTarget"></a>

### InstrumentCollectionRequest.Hook.AttachTarget



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| program_id | [uint32](#uint32) |  |  |
| subprog_name | [string](#string) |  |  |






<a name="datapathplugins-InstrumentCollectionResponse"></a>

### InstrumentCollectionResponse







<a name="datapathplugins-LocalNodeConfig"></a>

### LocalNodeConfig
LocalNodeConfig is Cilium&#39;s current config for this node. It may be used
by plugins to decide which hooks to load, how to configure them, etc.

TBD






<a name="datapathplugins-PrepareCollectionRequest"></a>

### PrepareCollectionRequest
Phase 1: As Cilium loads and prepares a collection for a particular
attachment point, it sends a PrepareHooksRequest to each plugin with context
about the attachment point, collection, and local node config. The plugin
decides which hooks it would like to insert, where it would like to insert
them, and informs Cilium in the PrepareHooksResponse.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| collection | [PrepareCollectionRequest.CollectionSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec) |  |  |
| local_node_config | [LocalNodeConfig](#datapathplugins-LocalNodeConfig) |  |  |
| attachment_context | [AttachmentContext](#datapathplugins-AttachmentContext) |  |  |
| config | [Config](#datapathplugins-Config) |  |  |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec"></a>

### PrepareCollectionRequest.CollectionSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| programs | [PrepareCollectionRequest.CollectionSpec.ProgramsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramsEntry) | repeated |  |
| maps | [PrepareCollectionRequest.CollectionSpec.MapsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapsEntry) | repeated |  |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-MapSpec"></a>

### PrepareCollectionRequest.CollectionSpec.MapSpec







<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-MapsEntry"></a>

### PrepareCollectionRequest.CollectionSpec.MapsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [PrepareCollectionRequest.CollectionSpec.MapSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapSpec) |  |  |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramSpec"></a>

### PrepareCollectionRequest.CollectionSpec.ProgramSpec







<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramsEntry"></a>

### PrepareCollectionRequest.CollectionSpec.ProgramsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [PrepareCollectionRequest.CollectionSpec.ProgramSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramSpec) |  |  |






<a name="datapathplugins-PrepareCollectionResponse"></a>

### PrepareCollectionResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hooks | [PrepareCollectionResponse.HookSpec](#datapathplugins-PrepareCollectionResponse-HookSpec) | repeated |  |
| cookie | [string](#string) |  | repeated MapReplacement map_replacements = 2; ... May be used by a plugin to associate a LoadHooksRequest with its preceding PrepareHooksRequest or carry other metadata between phases that may be helpful. |






<a name="datapathplugins-PrepareCollectionResponse-HookSpec"></a>

### PrepareCollectionResponse.HookSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [HookType](#datapathplugins-HookType) |  | PRE/POST (for now) |
| target | [string](#string) |  | Which program are we instrumenting? |
| constraints | [PrepareCollectionResponse.HookSpec.OrderingConstraint](#datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint) | repeated |  |






<a name="datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint"></a>

### PrepareCollectionResponse.HookSpec.OrderingConstraint
An OrderingConstraint is a constraint about where this hook should
go at this hook point relative to other plugins&#39; hooks.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| order | [PrepareCollectionResponse.HookSpec.OrderingConstraint.Order](#datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint-Order) |  |  |
| plugin | [string](#string) |  |  |





 


<a name="datapathplugins-HookType"></a>

### HookType


| Name | Number | Description |
| ---- | ------ | ----------- |
| PRE | 0 |  |
| POST | 1 |  |



<a name="datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint-Order"></a>

### PrepareCollectionResponse.HookSpec.OrderingConstraint.Order


| Name | Number | Description |
| ---- | ------ | ----------- |
| BEFORE | 0 |  |
| AFTER | 1 |  |


 

 


<a name="datapathplugins-DatapathPlugin"></a>

### DatapathPlugin


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| PrepareCollection | [PrepareCollectionRequest](#datapathplugins-PrepareCollectionRequest) | [PrepareCollectionResponse](#datapathplugins-PrepareCollectionResponse) |  |
| InstrumentCollection | [InstrumentCollectionRequest](#datapathplugins-InstrumentCollectionRequest) | [InstrumentCollectionResponse](#datapathplugins-InstrumentCollectionResponse) |  |

 



<a name="host_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## host_config.proto



<a name="datapathplugins-BPFHost"></a>

### BPFHost



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| allow_icmp_frag_needed | [bool](#bool) |  | Allow ICMP_FRAG_NEEDED messages when applying Network Policy. |
| device_mtu | [uint32](#uint32) |  | MTU of the device the bpf program is attached to (default: MTU set in node_config.h by agent). |
| enable_arp_responder | [bool](#bool) |  | Respond to ARP requests from local containers to resolve the default gateway. |
| enable_extended_ip_protocols | [bool](#bool) |  | Pass traffic with extended IP protocols. |
| enable_icmp_rule | [bool](#bool) |  | Apply Network Policy for ICMP packets. |
| enable_ipv4_fragments | [bool](#bool) |  | Enable IPv4 fragments tracking. |
| enable_ipv6_fragments | [bool](#bool) |  | Enable IPv6 fragments tracking. |
| enable_l2_announcements | [bool](#bool) |  | Enable L2 Announcements. |
| enable_netkit | [bool](#bool) |  | Use netkit devices for pods. |
| enable_no_service_endpoints_routable | [bool](#bool) |  | Enable routes when service has 0 endpoints. |
| enable_policy_accounting | [bool](#bool) |  | Maintain packet and byte counters for every policy entry. |
| enable_remote_node_masquerade | [bool](#bool) |  | Masquerade traffic to remote nodes. |
| ephemeral_min | [uint32](#uint32) |  | Ephemeral port range minimun. |
| eth_header_length | [uint32](#uint32) |  | Length of the Ethernet header on this device. May be set to zero on L2-less devices. (default __ETH_HLEN). |
| host_ep_id | [uint32](#uint32) |  | The host endpoint ID. |
| hybrid_routing_enabled | [bool](#bool) |  | Enable hybrid mode routing based on subnet IDs. |
| interface_ifindex | [uint32](#uint32) |  | Ifindex of the interface the bpf program is attached to. |
| interface_mac | [bytes](#bytes) |  | MAC address of the interface the bpf program is attached to. |
| l2_announcements_max_liveness | [uint64](#uint64) |  | If the agent is down for longer than the lease duration, stop responding. |
| nat_ipv4_masquerade | [bytes](#bytes) |  | Masquerade address for IPv4 traffic. |
| nat_ipv6_masquerade | [bytes](#bytes) |  | Masquerade address for IPv6 traffic. |
| proxy_redirect_via_cilium_net | [bool](#bool) |  | Whether to redirect to the proxy via cilium_net (hairpin) or via stack. |
| security_label | [uint32](#uint32) |  | The endpoint&#39;s security label. |
| tunnel_port | [uint32](#uint32) |  | Port number used for the overlay network. |
| tunnel_protocol | [uint32](#uint32) |  | The identifier of the tunnel protocol used for the overlay network. |
| vtep_mask | [uint32](#uint32) |  | VXLAN tunnel endpoint network mask. |
| wg_ifindex | [uint32](#uint32) |  | Index of the WireGuard interface. |
| wg_port | [uint32](#uint32) |  | Port for the WireGuard interface. |
| node | [Node](#datapathplugins-Node) |  |  |





 

 

 

 



<a name="lxc_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## lxc_config.proto



<a name="datapathplugins-BPFLXC"></a>

### BPFLXC



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| allow_icmp_frag_needed | [bool](#bool) |  | Allow ICMP_FRAG_NEEDED messages when applying Network Policy. |
| device_mtu | [uint32](#uint32) |  | MTU of the device the bpf program is attached to (default: MTU set in node_config.h by agent). |
| enable_arp_responder | [bool](#bool) |  | Respond to ARP requests from local containers to resolve the default gateway. |
| enable_extended_ip_protocols | [bool](#bool) |  | Pass traffic with extended IP protocols. |
| enable_icmp_rule | [bool](#bool) |  | Apply Network Policy for ICMP packets. |
| enable_ipv4_fragments | [bool](#bool) |  | Enable IPv4 fragments tracking. |
| enable_ipv6_fragments | [bool](#bool) |  | Enable IPv6 fragments tracking. |
| enable_lrp | [bool](#bool) |  | Enable support for Local Redirect Policy. |
| enable_netkit | [bool](#bool) |  | Use netkit devices for pods. |
| enable_no_service_endpoints_routable | [bool](#bool) |  | Enable routes when service has 0 endpoints. |
| enable_policy_accounting | [bool](#bool) |  | Maintain packet and byte counters for every policy entry. |
| enable_remote_node_masquerade | [bool](#bool) |  | Masquerade traffic to remote nodes. |
| endpoint_id | [uint32](#uint32) |  | The endpoint&#39;s security ID. |
| endpoint_ipv4 | [bytes](#bytes) |  | The endpoint&#39;s IPv4 address. |
| endpoint_ipv6 | [bytes](#bytes) |  | The endpoint&#39;s IPv6 address. |
| endpoint_netns_cookie | [uint64](#uint64) |  | The endpoint&#39;s network namespace cookie. |
| ephemeral_min | [uint32](#uint32) |  | Ephemeral port range minimun. |
| fib_table_id | [uint32](#uint32) |  | FIB routing table ID for egress lookups. |
| host_ep_id | [uint32](#uint32) |  | The host endpoint ID. |
| hybrid_routing_enabled | [bool](#bool) |  | Enable hybrid mode routing based on subnet IDs. |
| interface_ifindex | [uint32](#uint32) |  | Ifindex of the interface the bpf program is attached to. |
| interface_mac | [bytes](#bytes) |  | MAC address of the interface the bpf program is attached to. |
| nat_ipv4_masquerade | [bytes](#bytes) |  | Masquerade address for IPv4 traffic. |
| nat_ipv6_masquerade | [bytes](#bytes) |  | Masquerade address for IPv6 traffic. |
| policy_verdict_log_filter | [uint32](#uint32) |  | The log level for policy verdicts in workload endpoints. |
| proxy_redirect_via_cilium_net | [bool](#bool) |  | Whether to redirect to the proxy via cilium_net (hairpin) or via stack. |
| security_label | [uint32](#uint32) |  | The endpoint&#39;s security label. |
| tunnel_port | [uint32](#uint32) |  | Port number used for the overlay network. |
| tunnel_protocol | [uint32](#uint32) |  | The identifier of the tunnel protocol used for the overlay network. |
| vtep_mask | [uint32](#uint32) |  | VXLAN tunnel endpoint network mask. |
| node | [Node](#datapathplugins-Node) |  |  |





 

 

 

 



<a name="node_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## node_config.proto



<a name="datapathplugins-Node"></a>

### Node



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cilium_host_ifindex | [uint32](#uint32) |  | Interface index of the cilium_host device. |
| cilium_host_mac | [bytes](#bytes) |  | MAC address of the cilium_host device. |
| cilium_net_ifindex | [uint32](#uint32) |  | Interface index of the cilium_net device. |
| cilium_net_mac | [bytes](#bytes) |  | MAC address of the cilium_net device. |
| cluster_id | [uint32](#uint32) |  | Cluster ID. |
| cluster_id_bits | [uint32](#uint32) |  | Number of bits of the identity reserved for the Cluster ID. |
| debug_lb | [bool](#bool) |  | Enable debugging trace statements for load balancer. |
| direct_routing_dev_ifindex | [uint32](#uint32) |  | Index of the interface used to connect nodes in the cluster. |
| enable_conntrack_accounting | [bool](#bool) |  | Enable per flow (conntrack) statistics. |
| enable_jiffies | [bool](#bool) |  | Use jiffies (count of timer ticks since boot). |
| enable_tproxy | [bool](#bool) |  | Enable BPF-based proxy redirection. |
| hash_init4_seed | [uint32](#uint32) |  | Cluster-wide IPv4 tuple hash seed sourced. |
| hash_init6_seed | [uint32](#uint32) |  | Cluster-wide IPv6 tuple hash seed sourced. |
| kernel_hz | [uint32](#uint32) |  | Number of timer ticks per second. |
| nat_46x64_prefix | [bytes](#bytes) |  | NAT 46x64 prefix. |
| nodeport_port_max | [uint32](#uint32) |  | Nodeport maximum port value. |
| nodeport_port_min | [uint32](#uint32) |  | Nodeport minimum port value. |
| policy_deny_response_enabled | [bool](#bool) |  | Enable ICMP responses for policy-denied traffic. |
| router_ipv6 | [bytes](#bytes) |  | Internal IPv6 router address assigned to the cilium_host interface. |
| service_loopback_ipv4 | [bytes](#bytes) |  | IPv4 source address used for SNAT when a Pod talks to itself over a Service. |
| service_loopback_ipv6 | [bytes](#bytes) |  | IPv6 source address used for SNAT when a Pod talks to itself over a Service. |
| supports_fib_lookup_skip_neigh | [bool](#bool) |  | Whether or not BPF_FIB_LOOKUP_SKIP_NEIGH is supported. |
| trace_payload_len | [uint32](#uint32) |  | Length of payload to capture when tracing native packets. |
| trace_payload_len_overlay | [uint32](#uint32) |  | Length of payload to capture when tracing overlay packets. |
| tracing_ip_option_type | [uint32](#uint32) |  | The IP option type to use for packet tracing. |





 

 

 

 



<a name="overlay_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## overlay_config.proto



<a name="datapathplugins-BPFOverlay"></a>

### BPFOverlay



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| device_mtu | [uint32](#uint32) |  | MTU of the device the bpf program is attached to (default: MTU set in node_config.h by agent). |
| enable_extended_ip_protocols | [bool](#bool) |  | Pass traffic with extended IP protocols. |
| enable_ipv4_fragments | [bool](#bool) |  | Enable IPv4 fragments tracking. |
| enable_ipv6_fragments | [bool](#bool) |  | Enable IPv6 fragments tracking. |
| enable_netkit | [bool](#bool) |  | Use netkit devices for pods. |
| enable_no_service_endpoints_routable | [bool](#bool) |  | Enable routes when service has 0 endpoints. |
| enable_remote_node_masquerade | [bool](#bool) |  | Masquerade traffic to remote nodes. |
| encryption_strict_ingress | [bool](#bool) |  | Enable strict encryption for ingress traffic. |
| ephemeral_min | [uint32](#uint32) |  | Ephemeral port range minimun. |
| interface_ifindex | [uint32](#uint32) |  | Ifindex of the interface the bpf program is attached to. |
| interface_mac | [bytes](#bytes) |  | MAC address of the interface the bpf program is attached to. |
| nat_ipv4_masquerade | [bytes](#bytes) |  | Masquerade address for IPv4 traffic. |
| nat_ipv6_masquerade | [bytes](#bytes) |  | Masquerade address for IPv6 traffic. |
| proxy_redirect_via_cilium_net | [bool](#bool) |  | Whether to redirect to the proxy via cilium_net (hairpin) or via stack. |
| tunnel_port | [uint32](#uint32) |  | Port number used for the overlay network. |
| tunnel_protocol | [uint32](#uint32) |  | The identifier of the tunnel protocol used for the overlay network. |
| vtep_mask | [uint32](#uint32) |  | VXLAN tunnel endpoint network mask. |
| node | [Node](#datapathplugins-Node) |  |  |





 

 

 

 



<a name="sock_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## sock_config.proto



<a name="datapathplugins-BPFSock"></a>

### BPFSock



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enable_extended_ip_protocols | [bool](#bool) |  | Pass traffic with extended IP protocols. |
| enable_ipv4_fragments | [bool](#bool) |  | Enable IPv4 fragments tracking. |
| enable_ipv6_fragments | [bool](#bool) |  | Enable IPv6 fragments tracking. |
| enable_lrp | [bool](#bool) |  | Enable support for Local Redirect Policy. |
| enable_no_service_endpoints_routable | [bool](#bool) |  | Enable routes when service has 0 endpoints. |
| tunnel_port | [uint32](#uint32) |  | Port number used for the overlay network. |
| tunnel_protocol | [uint32](#uint32) |  | The identifier of the tunnel protocol used for the overlay network. |
| node | [Node](#datapathplugins-Node) |  |  |





 

 

 

 



<a name="wireguard_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## wireguard_config.proto



<a name="datapathplugins-BPFWireguard"></a>

### BPFWireguard



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| device_mtu | [uint32](#uint32) |  | MTU of the device the bpf program is attached to (default: MTU set in node_config.h by agent). |
| enable_extended_ip_protocols | [bool](#bool) |  | Pass traffic with extended IP protocols. |
| enable_ipv4_fragments | [bool](#bool) |  | Enable IPv4 fragments tracking. |
| enable_ipv6_fragments | [bool](#bool) |  | Enable IPv6 fragments tracking. |
| enable_netkit | [bool](#bool) |  | Use netkit devices for pods. |
| enable_no_service_endpoints_routable | [bool](#bool) |  | Enable routes when service has 0 endpoints. |
| enable_remote_node_masquerade | [bool](#bool) |  | Masquerade traffic to remote nodes. |
| ephemeral_min | [uint32](#uint32) |  | Ephemeral port range minimun. |
| interface_ifindex | [uint32](#uint32) |  | Ifindex of the interface the bpf program is attached to. |
| interface_mac | [bytes](#bytes) |  | MAC address of the interface the bpf program is attached to. |
| nat_ipv4_masquerade | [bytes](#bytes) |  | Masquerade address for IPv4 traffic. |
| nat_ipv6_masquerade | [bytes](#bytes) |  | Masquerade address for IPv6 traffic. |
| proxy_redirect_via_cilium_net | [bool](#bool) |  | Whether to redirect to the proxy via cilium_net (hairpin) or via stack. |
| tunnel_port | [uint32](#uint32) |  | Port number used for the overlay network. |
| tunnel_protocol | [uint32](#uint32) |  | The identifier of the tunnel protocol used for the overlay network. |
| node | [Node](#datapathplugins-Node) |  |  |





 

 

 

 



<a name="xdp_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## xdp_config.proto



<a name="datapathplugins-BPFXDP"></a>

### BPFXDP



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| device_mtu | [uint32](#uint32) |  | MTU of the device the bpf program is attached to (default: MTU set in node_config.h by agent). |
| enable_extended_ip_protocols | [bool](#bool) |  | Pass traffic with extended IP protocols. |
| enable_ipv4_fragments | [bool](#bool) |  | Enable IPv4 fragments tracking. |
| enable_ipv6_fragments | [bool](#bool) |  | Enable IPv6 fragments tracking. |
| enable_no_service_endpoints_routable | [bool](#bool) |  | Enable routes when service has 0 endpoints. |
| enable_remote_node_masquerade | [bool](#bool) |  | Masquerade traffic to remote nodes. |
| enable_xdp_prefilter | [bool](#bool) |  | Enable XDP Prefilter. |
| ephemeral_min | [uint32](#uint32) |  | Ephemeral port range minimun. |
| interface_ifindex | [uint32](#uint32) |  | Ifindex of the interface the bpf program is attached to. |
| interface_mac | [bytes](#bytes) |  | MAC address of the interface the bpf program is attached to. |
| nat_ipv4_masquerade | [bytes](#bytes) |  | Masquerade address for IPv4 traffic. |
| nat_ipv6_masquerade | [bytes](#bytes) |  | Masquerade address for IPv6 traffic. |
| proxy_redirect_via_cilium_net | [bool](#bool) |  | Whether to redirect to the proxy via cilium_net (hairpin) or via stack. |
| tunnel_port | [uint32](#uint32) |  | Port number used for the overlay network. |
| tunnel_protocol | [uint32](#uint32) |  | The identifier of the tunnel protocol used for the overlay network. |
| node | [Node](#datapathplugins-Node) |  |  |





 

 

 

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

