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
  and redirecting traffic to endpoints. For network-facing devices the
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

Combining the above hooks with virtual interfaces (cilium_host, cilium_net),
an optional overlay interface (cilium_vxlan), Linux kernel crypto support and
a userspace proxy (Envoy) Cilium creates the following networking objects.

* **Prefilter:** The prefilter object runs an XDP program and
  provides a set of prefilter rules used to filter traffic from the network for best performance. Specifically,
  a set of CIDR maps supplied by the Cilium agent are used to do a lookup and the packet
  is either dropped, for example when the destination is not a valid endpoint, or allowed to be processed by the stack. This can be easily
  extended as needed to build in new prefilter criteria/capabilities.

* **Endpoint Policy:** The endpoint policy object implements the Cilium endpoint enforcement.
  Using a map to lookup a packet's associated identity and policy, this layer
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

* **Socket Layer Enforcement:** Socket layer enforcement uses two
  hooks (the socket operations hook and the socket send/recv hook) to monitor
  and attach to all TCP sockets associated with Cilium managed endpoints, including
  any L7 proxies. The socket operations hook
  will identify candidate sockets for accelerating. These include all local node connections
  (endpoint to endpoint) and any connection to a Cilium proxy.
  These identified connections will then have all messages handled by the socket
  send/recv hook. The fast redirect ensures all policies implemented in Cilium are valid for the associated
  socket/endpoint mapping and assuming they are sends the message directly to the
  peer socket.

* **L7 Policy:** The L7 Policy object redirects proxy traffic to a Cilium userspace
  proxy instance. Cilium uses an Envoy instance as its userspace proxy. Envoy will
  then either forward the traffic or generate appropriate reject messages based on the configured L7 policy.

These components are connected to create the flexible and efficient datapath used
by Cilium. Below we show the following possible flows connecting endpoints on a single
node, ingress to an endpoint, and endpoint to egress networking device. In each case
there is an additional diagram showing the TCP accelerated path available when socket layer enforcement is enabled.
