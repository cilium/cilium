.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

############
Introduction
############

The Linux kernel supports a set of BPF hooks in the networking stack
that can be used to run BPF programs. The Cilium datapath uses these
hooks to load BPF programs that when used together create higher level
networking constructs.

The following is a list of the hooks used by Cilium and a brief
description. For a more thorough documentation on specifics of each
hook see :ref:`bpf_guide`.

* **XDP:** The XDP BPF hook is at the earliest point possible in the networking driver
  and triggers a run of the BPF program upon packet reception. This
  achieves the best possible packet processing performance since the
  program runs directly on the packet data before any other processing
  can happen. This hook is ideal for running filtering programs that
  drop malicious or unexpected traffic, and other common DDOS protection
  mechanisms.

* **Traffic Control Ingress/Egress:** BPF programs attached to the traffic
  control (tc) ingress hook are attached to a networking interface, same as
  XDP, but will run after the networking stack has done initial processing
  of the packet. The hook is run before the L3 layer of the stack but has
  access to most of the metadata associated with a packet. This is ideal
  for doing local node processing, such as applying L3/L4 endpoint policy
  and redirecting traffic to endpoints. For networking facing devices the
  tc ingress hook can be coupled with above XDP hook. When this is done it
  is reasonable to assume that the majority of the traffic at this
  point is legitimate and destined for the host.

  Containers typically use a virtual device called a veth pair which acts
  as a virtual wire connecting the container to the host. By attaching to
  the TC ingress hook of the host side of this veth pair Cilium can monitor
  and enforce policy on all traffic exiting a container. By attaching a BPF
  program to the veth pair associated with each container and routing all
  network traffic to the host side virtual devices with another BPF program
  attached to the tc ingress hook as well Cilium can monitor and enforce
  policy on all traffic entering or exiting the node.

  Depending on the use case, containers may also be connected through ipvlan
  devices instead of a veth pair. In this mode, the physical device in the
  host is the ipvlan master where virtual ipvlan devices in slave mode are
  set up inside the container. One of the benefits of ipvlan over a veth pair
  is that the stack requires less resources to push the packet into the
  ipvlan slave device of the other network namespace and therefore may
  achieve better latency results. This option can be used for unprivileged
  containers. The BPF programs for tc are then attached to the tc egress
  hook on the ipvlan slave device inside the container's network namespace
  in order to have Cilium apply L3/L4 endpoint policy, for example, combined
  with another BPF program running on the tc ingress hook of the ipvlan master
  such that also incoming traffic on the node can be enforced.

* **Socket operations:** The socket operations hook is attached to a specific
  cgroup and runs on TCP events. Cilium attaches a BPF socket operations
  program to the root cgroup and uses this to monitor for TCP state transitions,
  specifically for ESTABLISHED state transitions. When
  a socket transitions into ESTABLISHED state if the TCP socket has a node
  local peer (possibly a local proxy) a socket send/recv program is attached.

* **Socket send/recv:** The socket send/recv hook runs on every send operation
  performed by a TCP socket. At this point the hook can inspect the message
  and either drop the message, send the message to the TCP layer, or redirect
  the message to another socket. Cilium uses this to accelerate the datapath redirects
  as described below.

Combining the above hooks with a virtual interfaces (cilium_host, cilium_net),
an optional overlay interface (cilium_vxlan), Linux kernel crypto support and
a userspace proxy (Envoy) Cilium creates the following networking objects.

* **Prefilter:** The prefilter object runs an XDP program and
  provides a set of prefilter rules used to filter traffic from the network for best performance. Specifically,
  a set of CIDR maps supplied by the Cilium agent are used to do a lookup and the packet
  is either dropped, for example when the destination is not a valid endpoint, or allowed to be processed by the stack. This can be easily
  extended as needed to build in new prefilter criteria/capabilities.

* **Endpoint Policy:** The endpoint policy object implements the Cilium endpoint enforcement.
  Using a map to lookup a packets associated identity and policy this layer
  scales well to lots of endpoints. Depending on the policy this layer may drop the
  packet, forward to a local endpoint, forward to the service object or forward to the
  L7 Policy object for further L7 rules. This is the primary object in the Cilium
  datapath responsible for mapping packets to identities and enforcing L3 and L4 policies.

* **Service:** The Service object performs a map lookup on the destination IP
  and optionally destination port for every packet received by the object.
  If a matching entry is found, the packet will be forwarded to one of the
  configured L3/L4 endpoints. The Service block can be used to implement a
  standalone load balancer on any interface using the TC ingress hook or may
  be integrated in the endpoint policy object.

* **L3 Encryption:** On ingress the L3 Encryption object marks packets for
  decryption, passes the packets to the Linux xfrm (transform) layer for
  decryption, and after the packet is decrypted the object receives the packet
  then passes it up the stack for further processing by other objects. Depending
  on the mode, direct routing or overlay, this may be a BPF tail call or the
  Linux routing stack that passes the packet to the next object. The key required
  for decryption is encoded in the IPsec header so on ingress we do not need to
  do a map lookup to find the decryption key.

  On egress a map lookup is first performed using the destination IP to determine
  if a packet should be encrypted and if so what keys are available on the destination
  node. The most recent key available on both nodes is chosen and the
  packet is marked for encryption. The packet is then passed to the Linux
  xfrm layer where it is encrypted. Upon receiving the now encrypted packet
  it is passed to the next layer either by sending it to the Linux stack for
  routing or doing a direct tail call if an overlay is in use.

* **Socket Layer Enforcement:** Socket layer enforcement use two
  hooks the socket operations hook and the socket send/recv hook to monitor
  and attach to all TCP sockets associated with Cilium managed endpoints, including
  any L7 proxies. The socket operations hook
  will identify candidate sockets for accelerating. These include all local node connections
  (endpoint to endpoint) and any connection to a Cilium proxy.
  These identified connections will then have all messages handled by the socket
  send/recv hook and will be accelerated using sockmap fast redirects. The fast
  redirect ensures all policies implemented in Cilium are valid for the associated
  socket/endpoint mapping and assuming they are sends the message directly to the
  peer socket. This is allowed because the sockmap send/recv hooks ensures the message
  will not need to be processed by any of the objects above.

* **L7 Policy:** The L7 Policy object redirect proxy traffic to a Cilium userspace
  proxy instance. Cilium uses an Envoy instance as its userspace proxy. Envoy will
  then either forward the traffic or generate appropriate reject messages based on the configured L7 policy.

These components are connected to create the flexible and efficient datapath used
by Cilium. Below we show the following possible flows connecting endpoints on a single
node, ingress to an endpoint, and endpoint to egress networking device. In each case
there is an additional diagram showing the TCP accelerated path available when socket layer enforcement is enabled.

Scale
=====

.. _bpf_map_limitations:

BPF Map Limitations
-------------------

All BPF maps are created with upper capacity limits. Insertion beyond the limit
will fail and thus limits the scalability of the datapath. The following table
shows the default values of the maps. Each limit can be bumped in the source
code. Configuration options will be added on request if demand arises.

======================== ================ =============== =====================================================
Map Name                 Scope            Default Limit   Scale Implications
======================== ================ =============== =====================================================
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
======================== ================ =============== =====================================================

For some BPF maps, the upper capacity limit can be overridden using command
line options for ``cilium-agent``. A given capacity can be set using
``--bpf-ct-global-tcp-max``, ``--bpf-ct-global-any-max``,
``--bpf-nat-global-max``, ``--bpf-neigh-global-max``, ``--bpf-policy-map-max``,
and ``--bpf-fragments-map-max``.

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

Kubernetes Integration
======================

The following diagram shows the integration of iptables rules as installed by
kube-proxy and the iptables rules as installed by Cilium.

.. image:: _static/kubernetes_iptables.svg
