.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bpf_map_limitations:

eBPF Maps
=========

All BPF maps are created with upper capacity limits. Insertion beyond the limit
will fail and thus limits the scalability of the datapath. The following table
shows the default values of the maps. Each limit can be bumped in the source
code. Configuration options will be added on request if demand arises.

======================== ================ =============== =====================================================
Map Name                 Scope            Default Limit   Scale Implications
======================== ================ =============== =====================================================
Auth                     node             512k            Max 512k authenticated relations per node
Connection Tracking      node or endpoint 1M TCP/256k UDP Max 1M concurrent TCP connections, max 256k expected UDP answers
NAT                      node             512k            Max 512k NAT entries
Neighbor Table           node             512k            Max 512k neighbor entries
Endpoints                node             64k             Max 64k local endpoints + host IPs per node
IP cache                 node             512k            Max 256k endpoints (IPv4+IPv6), max 512k endpoints (IPv4 or IPv6) across all clusters
Load Balancer            node             64k             Max 64k cumulative backends across all services across all clusters
Policy                   endpoint         16k             Max 16k allowed identity + port + protocol pairs for specific endpoint
Proxy Map                node             512k            Max 512k concurrent redirected TCP connections to proxy
Tunnel                   node             64k             Max 32k nodes (IPv4+IPv6) or 64k nodes (IPv4 or IPv6) across all clusters
IPv4 Fragmentation       node             8k              Max 8k fragmented datagrams in flight simultaneously on the node
Session Affinity         node             64k             Max 64k affinities from different clients
IP Masq                  node             16k             Max 16k IPv4 cidrs used by BPF-based ip-masq-agent
Service Source Ranges    node             64k             Max 64k cumulative LB source ranges across all services
Egress Policy            endpoint         16k             Max 16k endpoints across all destination CIDRs across all clusters 
======================== ================ =============== =====================================================

For some BPF maps, the upper capacity limit can be overridden using command
line options for ``cilium-agent``. A given capacity can be set using
``--bpf-auth-map-max``, ``--bpf-ct-global-tcp-max``, ``--bpf-ct-global-any-max``,
``--bpf-nat-global-max``, ``--bpf-neigh-global-max``, ``--bpf-policy-map-max``,
``--bpf-fragments-map-max`` and ``--bpf-lb-map-max``.

.. Note::

   In case the ``--bpf-ct-global-tcp-max`` and/or ``--bpf-ct-global-any-max``
   are specified, the NAT table size (``--bpf-nat-global-max``) must not exceed
   2/3 of the combined CT table size (TCP + UDP). This will automatically be set
   if either ``--bpf-nat-global-max`` is not explicitly set or if dynamic BPF
   map sizing is used (see below).

Using the ``--bpf-map-dynamic-size-ratio`` flag, the upper capacity limits of
several large BPF maps are determined at agent startup based on the given ratio
of the total system memory. For example, a given ratio of 0.0025 leads to 0.25%
of the total system memory to be used for these maps.

This flag affects the following BPF maps that consume most memory in the system:
``cilium_ct_{4,6}_global``, ``cilium_ct_{4,6}_any``,
``cilium_nodeport_neigh{4,6}``, ``cilium_snat_v{4,6}_external`` and
``cilium_lb{4,6}_reverse_sk``.

``kube-proxy`` sets as the maximum number entries in the linux's connection
tracking table based on the number of cores the machine has. ``kube-proxy`` has
a default of ``32768`` maximum entries per core with a minimum of ``131072``
entries regardless of the number of cores the machine has.

Cilium has its own connection tracking tables as BPF Maps and the number of
entries of such maps is calculated based on the amount of total memory in the
node with a minimum of ``131072`` entries regardless the amount of memory the
machine has.

The following table presents the value that ``kube-proxy`` and Cilium sets for
their own connection tracking tables when Cilium is configured with
``--bpf-map-dynamic-size-ratio: 0.0025``.

+------+--------------+-----------------------+-------------------+
| vCPU | Memory (GiB) | Kube-proxy CT entries | Cilium CT entries |
+------+--------------+-----------------------+-------------------+
|    1 |         3.75 |                131072 |            131072 |
+------+--------------+-----------------------+-------------------+
|    2 |          7.5 |                131072 |            131072 |
+------+--------------+-----------------------+-------------------+
|    4 |           15 |                131072 |            131072 |
+------+--------------+-----------------------+-------------------+
|    8 |           30 |                262144 |            284560 |
+------+--------------+-----------------------+-------------------+
|   16 |           60 |                524288 |            569120 |
+------+--------------+-----------------------+-------------------+
|   32 |          120 |               1048576 |           1138240 |
+------+--------------+-----------------------+-------------------+
|   64 |          240 |               2097152 |           2276480 |
+------+--------------+-----------------------+-------------------+
|   96 |          360 |               3145728 |           4552960 |
+------+--------------+-----------------------+-------------------+
