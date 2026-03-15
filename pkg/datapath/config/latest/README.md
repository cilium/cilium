# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [host_config.proto](#host_config-proto)
    - [BPFHost](#latest-BPFHost)
  
- [lxc_config.proto](#lxc_config-proto)
    - [BPFLXC](#latest-BPFLXC)
  
- [node_config.proto](#node_config-proto)
    - [Node](#latest-Node)
  
- [overlay_config.proto](#overlay_config-proto)
    - [BPFOverlay](#latest-BPFOverlay)
  
- [sock_config.proto](#sock_config-proto)
    - [BPFSock](#latest-BPFSock)
  
- [wireguard_config.proto](#wireguard_config-proto)
    - [BPFWireguard](#latest-BPFWireguard)
  
- [xdp_config.proto](#xdp_config-proto)
    - [BPFXDP](#latest-BPFXDP)
  
- [Scalar Value Types](#scalar-value-types)



<a name="host_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## host_config.proto



<a name="latest-BPFHost"></a>

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
| node | [Node](#latest-Node) |  |  |





 

 

 

 



<a name="lxc_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## lxc_config.proto



<a name="latest-BPFLXC"></a>

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
| node | [Node](#latest-Node) |  |  |





 

 

 

 



<a name="node_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## node_config.proto



<a name="latest-Node"></a>

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



<a name="latest-BPFOverlay"></a>

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
| node | [Node](#latest-Node) |  |  |





 

 

 

 



<a name="sock_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## sock_config.proto



<a name="latest-BPFSock"></a>

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
| node | [Node](#latest-Node) |  |  |





 

 

 

 



<a name="wireguard_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## wireguard_config.proto



<a name="latest-BPFWireguard"></a>

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
| node | [Node](#latest-Node) |  |  |





 

 

 

 



<a name="xdp_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## xdp_config.proto



<a name="latest-BPFXDP"></a>

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
| node | [Node](#latest-Node) |  |  |





 

 

 

 



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

