.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _arch_guide:

############
Architecture
############

This document describes the Cilium architecture. It focuses on
documenting the BPF datapath hooks to implement the Cilium datapath, how
the Cilium datapath integrates with the container orchestration layer, and the
objects shared between the layers e.g. the BPF datapath and Cilium agent.

Datapath
============

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

* **Traffic Control Ingress:** BPF programs attached to the traffic control (tc)
  ingress hook are attached to a networking interface, same as XDP, but
  will run after the networking stack has done initial processing
  of the packet. The hook is run before the L3 layer of the stack but has access
  to most of the metadata associated with a packet. This is ideal for
  doing local node processing, such as applying L3/L4 endpoint policy
  and redirecting traffic to endpoints. For networking facing devices the
  tc ingress hook can be coupled with above XDP hook. When this is done  it
  is reasonable to assume that the majority of the traffic at this
  point is legitimate and destined for the host. Containers use a virtual device
  called a veth pair which acts as a virtual wire connecting the container to
  the host. By attaching to the TC ingress hook of the host side of this veth pair
  Cilium can monitor and enforce policy on all traffic exiting a container.
  By attaching a BPF program to the veth pair associated with each container and routing
  all network traffic to the host side virtual devices with another BPF program attached to
  the tc ingress hook as well Cilium can monitor and enforce policy on all traffic
  entering/exiting the node.

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
an optional overlay interface (cilium_vxlan) and a userspace proxy (Envoy) Cilium
creates the following networking objects.

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

Endpoint to Endpoint
--------------------
First we show the local endpoint to endpoint flow with optional L7 Policy on
egress and ingress. Followed by the same endpoint to endpoint flow with
socket layer enforcement enabled. With socket layer enforcement enabled for TCP
traffic the
handshake initiating the connection will traverse the endpoint policy object until TCP state
is ESTABLISHED. Then after the connection is ESTABLISHED only the L7 Policy
object is still required.

.. image:: /_static/cilium_bpf_endpoint.svg
   :target: /_static/cilium_bpf_endpoint.svg

Egress from Endpoint
--------------------

Next we show local endpoint to egress with optional overlay network. In the
optional overlay network traffic is forwarded out the Linux network interface
corresponding to the overlay. In the default case the overlay interface is
named cilium_vxlan. Similar to above, when socket layer enforcement is enabled
and a L7 proxy is in use we can avoid running the endpoint policy block between
the endpoint and the L7 Policy for TCP traffic.

.. image:: /_static/cilium_bpf_egress.svg
   :target: /_static/cilium_bpf_egress.svg

Ingress to Endpoint
-------------------

Finally we show ingress to local endpoint also with optional overlay network.
Similar to above socket layer enforcement can be used to avoid a set of
policy traversals between the proxy and the endpoint socket.

.. image:: /_static/cilium_bpf_ingress.svg
   :target: /_static/cilium_bpf_ingress.svg

This completes the datapath overview. More BPF specifics can be found in the
:ref:`bpf_guide`. Additional details on how to extend the L7 Policy
exist in the :ref:`envoy` section.

Kubernetes Integration
======================

The following diagram shows the integration of iptables rules as installed by
kube-proxy and the iptables rules as installed by Cilium.

.. image:: /_static/kubernetes_iptables.svg
   :target: /_static/kubernetes_iptables.svg
