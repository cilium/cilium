.. _arch_guide:

Architecture Guide
==================

The goal of this document is to describe the components of the Cilium architecture, and the different models for deploying Cilium within
your datacenter or cloud environment.  It focuses on the higher-level understanding required to run a full Cilium deployment.  You can then use the more detailed :ref:`admin_guide` to understand the details of setting up Cilium.

Cilium Components
-----------------

.. image:: images/cilium-arch.png
    :width: 600px
    :align: center
    :height: 300px

A deployment of Cilium consists of the following components running on each Linux container node
in the container cluster:

* **Cilium Agent:** Userspace daemon that interacts with the container runtime to setup networking for each  container. Provides an API
  for configuring network security policies, extracting network visibility data, etc.

* **Cilium CLI Client:** Simple CLI client for communicating with the local Cilium Agent, for example, to configure network security or visibility
  policies.

* **Linux Kernel BPF:** Integrated capability of the Linux kernel to accept compiled bytecode that is run at various hook/trace points within
  the kernel.  Cilium compiles BPF programs and has the kernel run them at key points in the network stack to have visibility and control over all
  network traffic in / out of all containers.

* **Container Platform Network Plugin:**  Each container platform (e.g., Docker, Kubernetes) has its own plugin
  model for how external networking platforms integrate.  In the case of Docker, each Linux
  node runs a process (cilium-docker) that handles each Docker libnetwork call and passes data / requests on
  to the main Cilium Agent.


In addition to the components that run on each Linux container host, Cilium leverages a key-value store to share data between Cilium Agents running on different nodes. The currently supported key-value stores are:

* etcd
* consul
* local storage (golang hashmap)


Cilium Agent
^^^^^^^^^^^^

The Cilium agent (cilium-agent) runs on each Linux container host.  At a high-level, the agent accepts configuration that describes
service-level network security and visibility policies.   It then listens to events in the container runtime to
learn when containers are started or stopped, and it creates custom BPF programs which the Linux kernel uses to control all
network access in / out of those containers.  In more detail, the agent:

* Exposes APIs to allow operations / security teams to configure security policies (see below) that control all communication between
  containers in the cluster.  These APIs also expose monitoring capabilities to gain additional visibility into network forwarding and filtering
  behavior.

* Gathers metadata about each new container that is created.  In particular, it queries identity metadata like container / pod labels, which are used
  to identify endpoints in Cilium security policies.

* Interacts with the container platforms network plugin to perform IP address management (IPAM), which controls what IPv4 and IPv6 addresses
  are assigned to each container.

* Combines its knowledge about container identity and addresses with the already configured security and visibility policies to generate highly
  efficient BPF programs that are tailored to the network forwarding and security behavior appropriate for each container.

* Compiles the BPF programs to bytecode using `clang/LLVM <https://clang.llvm.org/>`_ and passes them to the Linux kernel to run at
  for all packets in / out of the container's virtual ethernet device(s).


Cilium CLI Client
^^^^^^^^^^^^^^^^^

The Cilium CLI Client (cilium) is a command-line tool that is installed along with the Cilium Agent.  It gives a command-line
interface to interact with all aspects of the Cilium Agent API.   This includes
inspecting Cilium's state about each network
endpoint (i.e., container), configuring and viewing security policies, and configuring network monitoring behavior.

Linux Kernel BPF
^^^^^^^^^^^^^^^^

Berkeley Packet Filter (BPF) is a Linux kernel bytecode interpreter originally introduced
to filter network packets, e.g. tcpdump and socket filters. It has since been
extended with additional data structures such as hashtable and arrays as
well as additional actions to support packet mangling, forwarding,
encapsulation, etc. An in-kernel verifier ensures that BPF programs are safe
to run and a JIT compiler converts the bytecode to CPU architecture specific
instructions for native execution efficiency. BPF programs can be run at
various hooking points in the kernel such as for incoming packets, outgoing
packets, system calls, kprobes, etc.

BPF continues to evolve and gain additional capabilities with each new Linux release.
Cilium leverages BPF to perform core datapath filtering, mangling, monitoring and redirection,
and requires BPF capabilities that are in any Linux kernel version 4.8.0 or newer (the latest
current stable Linux kernel is 4.10.x).

Linux distros that focus on being a container runtime (e.g., CoreOS, Fedora Atomic)
typically already have default kernels that are newer than 4.8, but even recent
versions of general purpose operating systems, with the exception of Ubuntu 16.10,
are unlikely to have a default kernel that is 4.8+.  However, such OSes should support
installing and running an alternative kernel that is 4.8+.

For more detail on kernel versions, see: :ref:`admin_kernel_version` .

Key-Value Store
^^^^^^^^^^^^^^^

The Key-Value (KV) Store is used for the following state:

* Policy Identities: list of labels <=> policy identity identifier

* Global Services: global service id to VIP association (optional)

* Encapsulation VTEP mapping (optional)

To simplify things in a larger deployment, the key-value store can be the
same one used by the container
orchestrater (e.g., Kubernetes using etcd).  In single node Cilium deployments used for basic
testing / learning, Cilium can use a local store implemented as a golang hash map, avoiding the need to setup a dedicated K-V store.

Container IP Address Management and Connectivity
------------------------------------------------

Building microservices on top of container orchestrations platforms like
Docker and Kubernetes means that application architects assume the existence
of core platform capabilities like service discovery and service-based load-balancing
to map between a logical service identifier and the IP address assigned to the
containers/pods actually running that service.   This, along with the fact that
Cilium provides network security and visibility based on container identity, not
addressing, means that Cilium can keep the underlying network addressing model
extremely simple.

Cluster IP Prefixes and Container IP Assignment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

With Cilium, all containers in the cluster are connected to a single logical network,
which is associated with a single *cluster prefix*.  Cilium may have an IPv6 cluster
prefix and an IPv4 cluster prefix, in which case a container gets addresses of
both types, or just a single cluster prefix.

The simplest approach is to use a private address space, though there are some scenarios
where you would choose to use publicly routable addresses (see the next section on IP
Interconnectivity).

Each Linux node running containers gets a ''node prefix'' out of the larger cluster prefix,
and uses it to assign IPs to its local containers.   Cilium chooses the node prefix for
a node deterministically based on the IP address of the node itself, so that for a given
destination container address, it is possible for Cilium to map directly to the IP address of
the corresponding node (this is useful when performing Overlay Routing, as
desribed in the following section).

IPv6 IP Address Assignment
~~~~~~~~~~~~~~~~~~~~~~~~~~

TODO:  I'd like to know what the logic to assign addresses. Especially, are those addresses assigned sequentially? Are they randomly chosen from available addresses in the prefix? What is the delay before an IPv6 address is reused? Is all that information persisted? Where? Is there really no risk of assigning the same IPv6 address twice?

Cilium allocates addresses for all containers from a single ``/48`` IPv6
prefix called the cluster prefix. If left unspecified, this prefix will
be ``f00d::/48``. Within that prefix, a ``/96`` prefix is dedicated to
each node in the cluster. Although the default prefix will enable
communication within an isolated environment, the prefix is not publicly
routable. It is strongly recommended to specify a public prefix owned by
the user using the ``--node-addr`` option.

If no node address is specified, Cilium will try and generate a unique
node prefix by using the first global scope IPv4 address as a 32 bit
node identifier, e.g. ``f00d:0:0:0:<ipv4-address>::/96``. Within that
``/96`` prefix, each node will independently allocate addresses for
local containers.

Note that only 16 bits out of the ``/96`` node prefix are currently used
when allocating container addresses. This allows to use the remaining 16
bits to store arbitrary connection state when sending packets between
nodes. A typical use for the state is direct server return.

Assuming 32 bits are being used to identify nodes, this leaves another
48 bits unused which can be used to store state when extending Cilium.
The specific allocation of bits in the ``/48`` cluster prefix is
entirely in the control of the user.

Based on the node prefix, two node addresses are automatically generated
by replacing the last 32 bits of the address with ``0:0`` and
``0:ffff`` respectively. The former is used as the next-hop address for the default
route inside containers, i.e. all packets from a container will be sent
to that address for further routing. The latter represents the Linux
stack and is used to reach the local network stack, e.g. Kubernetes
health checks.

Example
```````

::

    Cluster prefix: f00d::/48

    Node A prefix:  f00d:0:0:0:A:A::/96
    Node A address: f00d:0:0:0:A:A:0:0/128
    Container on A: f00d:0:0:0:A:A:0:1111/128

    Node B prefix:  f00d:0:0:0:B:B::/96
    Node B address: f00d:0:0:0:B:B:0:0/128
    Container on B: f00d:0:0:0:B:B:0:2222/128

IPv4 IP Address Assignment
~~~~~~~~~~~~~~~~~~~~~~~~~~

Cilium will allocate IPv4 addresses to containers out of a ``/16`` node
prefix. This prefix can be specified with the ``--ipv4-range`` option.
If left unspecified, Cilium will try and generate a unique prefix using
the format ``10.X.0.0/16`` where X is replaced with the last byte of the
first global scope IPv4 address discovered on the node. This generated
prefix is relatively weak in uniqueness so it is highly recommended to
always specify the IPv4 range.

The address ``10.X.0.1`` is reserved and represents the local node.

.. _arch_ip_connectivity:

IP Interconnectivity
--------------------

When thinking about base IP connectivity with Cilium, its useful to consider two
different types of connectivity:

* Container-to-Container Connectivity

* Container Communication with External Hosts

Container-to-Container Connectivity
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TODO: Simplify

In the case of connectivity between two containers in the cluster, Cilium processes
packets on both ends of the connection.  It uses the packet headers (either unused bits
in the IPv6 header, or fields in the encapsulation header in the case of IPv4) to
maintain context about the identity of the sending container that is used when making packet filtering
decisions at the destination node.

There are two possible approaches to performing network forwarding for container-to-container
traffic:

* **Direct Routing:**  In this mode, Cilium will hand all packets which are not
  addresses to a local container and not addresses to the local node to
  the Linux stack causing it to route the packet as it would route any
  other non-local packet. As a result, the network connecting the Linux node hosts must be aware that each of the
  node IP prefixes are reachable
  by using the node's primary IP address as an L3 next hop address.   In the case of a traditional
  physical network this would typically involve announcing each node prefix as a route using a routing
  protocol within the datacenter. Cloud providers (e.g, AWS VPC, or GCE) provide APIs to achieve the same result.

* **Overlay Routing:** In this mode, the network connecting the Linux node hosts are never aware of the
  node IP prefixes.  Instead, because
  Cilium can deterministically map from any container IP address to the corresponding node IP address,
  Cilium can look at the destination IP address of any packet destined to a container, and then use UDP
  encapsulation to send the packet directly to the IP address of the node running that container.  The
  destination node then decapsulates the packet, and delivers it to the local container.
  Because overlay routing requires no configuration changes in the underlying network, it is often the
  easiest approach to adopt initially.

Regardless of the option chosen, the container itself has no awareness
of the underlying network it runs on, it only contains a default route
which points to the IP address of the node. Given the removal of the
routing cache in the Linux kernel, this reduces the amount of state to
keep to the per connection flow cache (TCP metrics) which allows to
terminate millions of connections in each container.

Container Communication with External Hosts
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Container communication with the outside world has two primary modes:

 * Containers exposing API services for consumption by hosts outside of the container cluster.

 * Containers making outgoing connections.  Examples include connecting to 3rd-party API services
   like Twillio or Stripe as well as accessing private APIs that are hosted elsewhere in your enterprise
   datacenter or cloud deployment.

In the ''Direct Routing'' scenario described above, if container IP addresses are routable outside of the
container cluster, communication with external hosts requires little more than enabling L3 forwarding on
each of the Linux nodes.

External Connectivity with Overlay Routing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

However, in the case of ''Overlay Routing'', accessing external hosts requires additional configuration.

In the case of containers accepting inbound connections, such services are likely exposed via
some kind of load-balancing layer, where the load-balancer has an external address that is not
part of the Cilium network.  This can be achieved by having a load-balancer container that both has a
public IP on an externally reachable network and a private IP on a cilium network. However, many container
orchestrater frameworks, like Kubernetes, have built in abstractions to handle this "ingress" load-balancing
capability, which achieve the same effect that Cilium handles forwarding and security only for
''internal'' traffic between different services.

Containers that simply need to make outgoing connections to external hosts can be addressed by
configuring each Linux node host to masquerade connections from containers to IP ranges other than the
cluster prefix (IP masquerading is also known as Network Address Port Translation,
or NAPT).  This approach can be used even if there is a mismatch between the IP version used
for the container prefix and the version used for Node IP addresses.

Security Policies
-----------------

TODO: tgraf to complete this section

- label-based filtering
- inbound + outbound filtering rules
- L3 / L4 filtering (deny behavior is a drop)
- HTTP-aware filtering (IPv4-only, deny behavior if a HTTP 403)
- stateful filtering / conn tracking
- where is filtering performed?
- Policy persistence / distribution model
- Policy hierarchy (root, etc.)
- reserved keywords (e.g., world)

Integration with Container Platforms
------------------------------------

Cilium is deeply integrated with container platforms like Docker or Kubernetes.
This enables Cilium
to perform network forwarding and security using a model that maps direction to
notions of identity (e.g., labels) and service abstractions that are native to
the container platform.

In this section, we will provide more detail on how Cilium integrates with Docker and Kubernetes.

Docker Integration
^^^^^^^^^^^^^^^^^^

Docker supports network plugins via the `libnetwork plugin interface
<https://github.com/docker/libnetwork/blob/master/docs/design.md>`_ .

When using Cilium with Docker, one creates a single logical Docker network of type ''cilium'' and with an
IPAM-driver of type ''cilium'', which delegates control over IP address management and network connectivity
to Cilium for all containers attached to this network for both IPv4 and IPv6 connectivity.
Each Docker container gets an IP address from the node prefix of the node running the container.

When deployed with
Docker, each Linux node runs a ''cilium-docker'' agent, which receives libnetwork calls from Docker and
then communicates with the Cilium Agent to control container networking.

Security policies controlling connectivity between the Docker containers can be written in terms of the
Docker container labels passed to Docker when creating the container.  These policies can be created/updated
via communication directly with the Cilium agent, either via API or using the Cilium CLI client.

Kubernetes Integration
^^^^^^^^^^^^^^^^^^^^^^

When deployed with Kubernetes, Cilium provides four core Kubernetes networking capabilities:

* Direct pod-to-pod network inter-connectivity.
* Service-based load-balancing for pod-to-pod inter-connectivity (i.e., a kube-proxy replacement).
* Identity-based security policies for all  (direct and service-based) Pod-to-Pod inter-connectivity.
* External-to-Pod service-based load-balancing (referred to as ''Ingress'' in Kubernetes)

The Kubernetes documentation contains more background on the `Kubernetes Networking Model
<https://kubernetes.io/docs/concepts/cluster-administration/networking/>`_ and
`Kubernetes Network Plugins <https://kubernetes.io/docs/concepts/cluster-administration/network-plugins/>`_ .

Direct Pod-to-Pod Connectivity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In Kubernetes, containers are deployed within units referred to as Pods, which include one or more
containers reachable via a single IP address.  With Cilium, each Pod gets an IP address from the
node prefix of the Linux node running the Pod.   In the absence of any network security policies,
all Pods can reach each other.

Pod IP addresses are typically local to the Kubernetes cluster.  If pods need to reach services
outside the cluster as a client, the Kubernetes nodes are typically configured
to IP masquerade all traffic sent from containers to external prefix.

Pod-to-Pod Service-based Load-balancing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Kubernetes has developed the Services abstration which provides the user
the ability to load balance network traffic to different pods. This
abstraction allows the pods reaching out to other pods by a single IP
address, a virtual IP address, without knowing all the pods that are
running that particular service.

Without Cilium, kube-proxy is installed on every node, watches for endpoints and services
addition and removal on the kube-master which allows it to to apply the
necessary enforcement on iptables. Thus, the received and sent traffic
from and to the pods are properly routed to the node and port serving
for that service. For more information you can check out the kubernetes
user guide for `Services  <http://kubernetes.io/docs/user-guide/services>`__ .

Cilium loadbalancer acts on the same principles as kube-proxy, it
watches for services addition or removal, but instead of doing the
enforcement on the iptables, it updates bpf maps entries on
each node. For more information, see the `Pull Request
<https://github.com/cilium/cilium/pull/109>`__ .

TODO: describe benefits of BPF based load-balancer compared to kube-proxy iptables

Identity-based Security Policies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With Kubernetes, Cilium sees each deployed Pod as an individual endpoint for security policy enforcement.
Cilium can enforce both L3/L4 security policies and L7 HTTP-aware security policies.  Endpoints are identified
in Cilium policies using Kubernetes pod labels, meaning that policies can be described using endpoint identity
rather than addresses.   Cilium enforcement
affects both direct pod-to-pod communication, as well as service-based communication that is originally sent to
the ''cluster ip'' of a service, and is sent to a particular pod by the kube-proxy load-balancer (or in the case of
Cilium, the Cilium load-balancer).

L3/L4 policies can either be configured directly via Cilium in the Cilium policy language, or they can be specified
by as `Kubernetes Network Policies <https://kubernetes.io/docs/user-guide/networkpolicies/>`_ , in which case
the Cilium Kubernetes network plugin translates the Kubernetes Network Policies into Cilium policies and automatically
keeps them in sync.  For more details on Kubernetes Network Policies, see:

TODO: One major difference that is omitted in the comparison between Cilium policies and K8s policies, is that K8s policies are defined globally, for the whole cluster, whereas Cilium policies must be configured on every node.

.. toctree::

   policy

It is important to note that there are key differences between Kubernetes Network Policies and
Cilium L3/L4 policies.  Most importantly, Kubernetes Network Policies only control ''ingress''
connections (i.e., connections ''into''a container) but are not able to control ''egress'' connections (i.e.,
connections ''out'' of a container).

Kubernetes does not yet have a mechanism for specifying L7 HTTP-aware security policies, so such policies must
be configured directly via Cilium, using Pod labels to identify endpoints.   Cilium's policy model is rich enough
to support a ''mixed'' scenario
where L3/L4 policies are defined via Kubernetes Network Policies and L7 policies are defined directly in Cilium.

External-to-Pod Service-based Load-balancing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TODO: Verify this

Kubernetes supports an abstraction known as `Ingress <https://kubernetes.io/docs/user-guide/ingress/#what-is-ingress>`_
that allows a Pod-based Kubernetes service to expose itself for access outside of the cluster in a load-balanced way.
In a typical setup, the external traffic would be sent to a publicly reachable IP + port on the host running the
Kubernetes master, and then be load-balanced to the pods implementing the current service within the cluster.

Cilium supports Ingress with TCP-based load-balancing.  Moreover, it supports ''direct server return'', meaning that
reply traffic from the pod to the external client is sent directly, without needing to pass through the kubernetes
master host.

TODO: insert graphic showing LB + DSR.


