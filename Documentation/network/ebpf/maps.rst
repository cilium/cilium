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
Service Load Balancer    node             64k             Max ~3k clusterIP/nodePort Services across all clusters (see: `service map sizing <#service-lb-map-sizing>`_ section for details).
Service Backends         node             64k             Max 64k cumulative unique backends across all services across all clusters
Policy                   endpoint         16k             Max 16k allowed identity + port + protocol pairs for specific endpoint
Proxy Map                node             512k            Max 512k concurrent redirected TCP connections to proxy
Tunnel                   node             64k             Max 32k nodes (IPv4+IPv6) or 64k nodes (IPv4 or IPv6) across all clusters
IPv4 Fragmentation       node             8k              Max 8k fragmented datagrams in flight simultaneously on the node
Session Affinity         node             64k             Max 64k affinities from different clients
IPv4 Masq                node             16k             Max 16k IPv4 cidrs used by BPF-based ip-masq-agent
IPv6 Masq                node             16k             Max 16k IPv6 cidrs used by BPF-based ip-masq-agent
Service Source Ranges    node             64k             Max 64k cumulative LB source ranges across all services
Egress Policy            endpoint         16k             Max 16k endpoints across all destination CIDRs across all clusters 
Node                     node             16k             Max 16k distinct node IPs (IPv4 & IPv6) across all clusters.
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

.. _svc_lb_tuning:

Service LB Map Sizing
=====================

Cilium uses the LB services maps named ``cilium_lb{4,6}_services_v2`` to hold Service load balancer entries for clusterIP and nodePort service types.
These maps are configured via the ``--bpf-lb-map-max`` flag and are set to 64k by default. If this map is full, Cilium may be unable to reconcile Service
updates which may affect connectivity to service IPs or the ability to create new services.

The required size of service LB maps depends on multiple factors. Each clusterIP/nodePort service will create
a number of entries equal to the number of Pods backends selected by the service, times the number of port/protocol entries in the respective Service spec.

:math:`\text{LB map entries per Service} = (\text{number of endpoints per service}) * (\text{number of port/protocols per service})`

Using this, we can roughly the required map size as:

:math:`\text{LB map entries} \approx (\text{number of LB services}) * (\text{avg number of endpoints per service}) * (\text{avg number of port/protocols per service})`

.. note::

   This heuristic assumes that number of selected Pods and ports/protocol entries per service are roughly normally distributed. If your use case
   has large outliers (ex. such as a service that selects a very large set of Pod backends) it may be necessary to do a more detailed estimate.

Once Cilium has created the service LB maps for a Node (i.e. upon first running Cilium agent on a Node), attempting to resize the map size
parameter and restarting Cilium results in connection disruptions as the new map is repopulated with existing service entries.
Therefore it is important to carefully consider map requirements prior to installing Cilium if such disruptions are a concern.

