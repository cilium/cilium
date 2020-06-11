.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Maps
====

All BPF maps are created with upper capacity limits. Insertion beyond the limit
will fail and thus limits the scalability of the datapath. The following table
shows the default values of the maps. Each limit can be bumped in the source
code. Configuration options will be added on request if demand arises.

======================== ================ =============== =====================================================
Map Name                 Scope            Default Limit   Scale Implications
======================== ================ =============== =====================================================
Connection Tracking      node or endpoint 1M TCP/256k UDP Max 1M concurrent TCP connections, max 256k expected UDP answers
NAT                      node             512k            Max 512k NAT entries
Endpoints                node             64k             Max 64k local endpoints + host IPs per node
IP cache                 node             512k            Max 256k endpoints (IPv4+IPv6), max 512k endpoints (IPv4 or IPv6) across all clusters
Load Balancer            node             64k             Max 64k cumulative backends across all services across all clusters
Policy                   endpoint         16k             Max 16k allowed identity + port + protocol pairs for specific endpoint
Proxy Map                node             512k            Max 512k concurrent redirected TCP connections to proxy
Tunnel                   node             64k             Max 32k nodes (IPv4+IPv6) or 64k nodes (IPv4 or IPv6) across all clusters
IPv4 Fragmentation       node             8k              Max 8k fragmented datagrams in flight simultaneously on the node
======================== ================ =============== =====================================================

For some BPF maps, the upper capacity limit can be overridden using command
line options for ``cilium-agent``. A given capacity can be set using
``--bpf-ct-global-tcp-max``, ``--bpf-ct-global-any-max``,
``--bpf-nat-global-max``, ``--bpf-policy-map-max``, and
``--bpf-fragments-map-max``.

Using ``--bpf-map-dynamic-size-ratio`` the upper capacity limits of the
connection tracking, NAT, and policy maps are determined at agent startup based
on the given ratio of the total system memory. For example a given ratio of 0.03
leads to 3% of the total system memory to be used for these maps.
