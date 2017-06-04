.. _arch_guide:

##################
Architecture Guide
##################

The goal of this document is to describe the components of the Cilium
architecture, and the different models for deploying Cilium within your
datacenter or cloud environment.  It focuses on the higher-level understanding
required to run a full Cilium deployment.  You can then use the more detailed
:ref:`admin_guide` to understand the details of setting up Cilium.

*****************
Cilium Components
*****************

.. image:: images/cilium-arch.png
    :width: 600px
    :align: center
    :height: 300px

A deployment of Cilium consists of the following components running on each
Linux container node in the container cluster:

* **Cilium Agent (Daemon):** Userspace daemon that interacts with the container runtime
  and orchestration systems such as Kubernetes via Plugins to setup networking
  and security for containers running on the local server.  Provides an API for
  configuring network security policies, extracting network visibility data,
  etc.

* **Cilium CLI Client:** Simple CLI client for communicating with the local
  Cilium Agent, for example, to configure network security or visibility
  policies.

* **Linux Kernel BPF:** Integrated capability of the Linux kernel to accept
  compiled bytecode that is run at various hook / trace points within the kernel.
  Cilium compiles BPF programs and has the kernel run them at key points in the
  network stack to have visibility and control over all network traffic in /
  out of all containers.

* **Container Platform Network Plugin:**  Each container platform (e.g.,
  Docker, Kubernetes) has its own plugin model for how external networking
  platforms integrate.  In the case of Docker, each Linux node runs a process
  (cilium-docker) that handles each Docker libnetwork call and passes data /
  requests on to the main Cilium Agent.


In addition to the components that run on each Linux container host, Cilium
leverages a key-value store to share data between Cilium Agents running on
different nodes. The currently supported key-value stores are:

* etcd
* consul
* local storage (golang hashmap)


Cilium Agent
============

The Cilium agent (cilium-agent) runs on each Linux container host.  At a
high-level, the agent accepts configuration that describes service-level
network security and visibility policies.   It then listens to events in the
container runtime to learn when containers are started or stopped, and it
creates custom BPF programs which the Linux kernel uses to control all network
access in / out of those containers.  In more detail, the agent:

* Exposes APIs to allow operations / security teams to configure security
  policies (see below) that control all communication between containers in the
  cluster.  These APIs also expose monitoring capabilities to gain additional
  visibility into network forwarding and filtering behavior.

* Gathers metadata about each new container that is created.  In particular, it
  queries identity metadata like container / pod labels, which are used to
  identify endpoints in Cilium security policies.

* Interacts with the container platforms network plugin to perform IP address
  management (IPAM), which controls what IPv4 and IPv6 addresses are assigned
  to each container. The IPAM is managed by the agent in a shared pool between
  all plugins which means that the Docker and CNI network plugin can run side
  by side allocating a single address pool.

* Combines its knowledge about container identity and addresses with the
  already configured security and visibility policies to generate highly
  efficient BPF programs that are tailored to the network forwarding and
  security behavior appropriate for each container.

* Compiles the BPF programs to bytecode using `clang/LLVM
  <https://clang.llvm.org/>`_ and passes them to the Linux kernel to run for
  all packets in / out of the container's virtual ethernet device(s).


Cilium CLI Client
=================

The Cilium CLI Client (cilium) is a command-line tool that is installed along
with the Cilium Agent.  It gives a command-line interface to interact with all
aspects of the Cilium Agent API.   This includes inspecting Cilium's state
about each network endpoint (i.e., container), configuring and viewing security
policies, and configuring network monitoring behavior.

Linux Kernel BPF
================

Berkeley Packet Filter (BPF) is a Linux kernel bytecode interpreter originally
introduced to filter network packets, e.g. tcpdump and socket filters. It has
since been extended with additional data structures such as hashtable and
arrays as well as additional actions to support packet mangling, forwarding,
encapsulation, etc. An in-kernel verifier ensures that BPF programs are safe to
run and a JIT compiler converts the bytecode to CPU architecture specific
instructions for native execution efficiency. BPF programs can be run at
various hooking points in the kernel such as for incoming packets, outgoing
packets, system calls, kprobes, etc.

BPF continues to evolve and gain additional capabilities with each new Linux
release.  Cilium leverages BPF to perform core datapath filtering, mangling,
monitoring and redirection, and requires BPF capabilities that are in any Linux
kernel version 4.8.0 or newer. On the basis that 4.8.x is already declared end
of life and 4.9.x has been nominated as a stable release we recommend to run at
least kernel 4.9.17 (the latest current stable Linux kernel as of this writing
is 4.10.x).

Cilium is capable of probing the Linux kernel for available features and will
automatically make use of more recent features as they are detected.

Linux distros that focus on being a container runtime (e.g., CoreOS, Fedora
Atomic) typically already ship kernels that are newer than 4.8, but even recent
versions of general purpose operating systems such as Ubuntu 16.10 ship fairly
recent kernels. Some Linux distributions still ship older kernels but many of
them allow installing recent kernels from separate kernel package repositories.

For more detail on kernel versions, see: :ref:`admin_kernel_version`.

Key-Value Store
===============

The Key-Value (KV) Store is used for the following state:

* Policy Identities: list of labels <=> policy identity identifier

* Global Services: global service id to VIP association (optional)

* Encapsulation VTEP mapping (optional)

To simplify things in a larger deployment, the key-value store can be the same
one used by the container orchestrater (e.g., Kubernetes using etcd).  In
single node Cilium deployments used for basic testing / learning, Cilium can
use a local store implemented as a golang hash map, avoiding the need to setup
a dedicated KV store.

******
Labels
******

Labels are a generic, flexible and highly scaleable way of addressing a large
set of resources as they allow for arbitrary grouping and creation of sets.
Whenever something needs to be descried, addressed or selected this is done
based on labels:

- Endpoints are assigned labels as derived from container runtime or the
  orchestration system.
- Network policies select endpoints based on labels and allow consumers based
  on labels.
- Network policies themselves are described and addressed by labels.

Basic Label: Key/Value Pair
---------------------------

A label is a pair of strings consisting of a ``key`` and ``value``. A label can
be formatted as a single string with the format ``key=value``. The key portion
is mandatory and must be unique. This is typically achieved by using the
reverse domain name notion, e.g. ``io.cilium.mykey=myvalue``. The value portion
is optional and can be omitted, e.g. ``io.cilium.mykey``.

Key names should typically consist of the character set ``[a-z0-9-.]``.

When using labels to select resources, both the key and the value must match,
e.g. when a policy should be applied to all endpoints will label
``my.corp.foo`` then the label ``my.corp.foo=bar`` will not match the
selector.

Label Source
------------

A label can be derived from various sources. For example, a Cilium endpoint
will derive the labels associated to the container by the local container
runtime as well as the labels associated with the pod as provided by
Kubernetes. As these two label namespaces are not aware of each other, this may
result in conflicting label keys.

To resolve this potential conflict, Cilium prefixes all label keys with
``source:`` to indicate the source of the label when importing labels, e.g.
``k8s:role=frontend``, ``container:user=joe``, ``k8s:role=backend``. This means
that when you run a Docker container using ``docker run [...] -l foo=bar``, the
label ``container:foo=bar`` will appear on the Cilium endpoint representing the
container. Similiarly, a Kubernetes pod started with the label ``foo: bar``
will be represented with a Cilium endpoint associated with the label
``k8s:foo=bar``. A unique name is allocated for each potential source. The
following label sources are currently supported:

- ``container:`` for labels derived from the local container runtime
- ``k8s:`` for labels derived from Kubernetes
- ``reserved:`` for special reserved labels, see :ref:`reserved_labels`.
- ``unspec:`` for labels with unspecified source

When using labels to identify other resources, the source can be included to
limit matching of labels to a particular type. If no source is provided, the
label source defaults to ``any:`` which will match all labels regardless of
their source. If a source is provided, the source of the selecting and matching
labels need to match.

******************
Address Management
******************

Building microservices on top of container orchestrations platforms like Docker
and Kubernetes means that application architects assume the existence of core
platform capabilities like service discovery and service-based load-balancing
to map between a logical service identifier and the IP address assigned to the
containers / pods actually running that service.   This, along with the fact that
Cilium provides network security and visibility based on container identity,
not addressing, means that Cilium can keep the underlying network addressing
model extremely simple.

Cluster IP Prefixes and Container IP Assignment
===============================================

With Cilium, all containers in the cluster are connected to a single logical
Layer 3 network, which is associated a single *cluster wide address prefix*.
This means that all containers or endpoint connected to Cilium share a single
routable subnet. Hence, all endpoints have the capability of reaching each
other with two routing operations performed (one routing operation is performed
on both the origin and destination container host). Cilium supports IPv4 and
IPv6 addressing in parallel, i.e. each container can be assigned an IPv4 and
IPv6 address and these addresses can be used exchangeably.

The simplest approach is to use a private address space for the cluster wide
address prefix. However there are scenarios where choosing a publicly routable
addresses is preferred, in particular in combination with IPv6 where acquiring
a large routeable addressing subnet is possible. (See the next section on IP
Interconnectivity).

Each container host is assigned  a *node prefix* out of the *cluster prefix*
which is used to allocate IPs for local containers.  Based on this, Cilium is
capable of deriving the container host IP address of any container and
automatically create a logical overlay network without further configuration.
See section *Overlay Routing* for additional details.


IPv6 IP Address Assignment
--------------------------

Cilium allocates addresses for local containers from the ``/48`` IPv6 prefix
called the *cluster prefix*. If left unspecified, this prefix will be
``f00d::/48``.  Within that prefix, a ``/96`` prefix is dedicated to each
container host in the cluster. Although the default prefix will enable
communication within an isolated environment, the prefix is not publicly
routable. It is strongly recommended to specify a public prefix owned by the
user using the ``--node-addr`` option.

If no node address is specified, Cilium will try to generate a unique node
prefix by using the first global scope IPv4 address as a 32 bit node
identifier, e.g. ``f00d:0:0:0:<ipv4-address>::/96``. Within that ``/96``
prefix, each node will independently allocate addresses for local containers.

Note that only 16 bits out of the ``/96`` node prefix are currently used when
allocating container addresses. This allows to use the remaining 16 bits to
store arbitrary connection state when sending packets between nodes. A typical
use for the state is direct server return.

Based on the node prefix, two node addresses are automatically generated by
replacing the last 32 bits of the address with ``0:0`` and ``0:ffff``
respectively. The former is used as the next-hop address for the default route
inside containers, i.e. all packets from a container will be sent to that
address for further routing. The latter represents the Linux stack and is used
to reach the local network stack, e.g. Kubernetes health checks.

TODO:  I'd like to know what the logic to assign addresses. Especially, are
those addresses assigned sequentially? Are they randomly chosen from available
addresses in the prefix? What is the delay before an IPv6 address is reused? Is
all that information persisted? Where? Is there really no risk of assigning the
same IPv6 address twice?

Example
^^^^^^^

::

    Cluster prefix: f00d::/48

    Node A prefix:  f00d:0:0:0:A:A::/96
    Node A address: f00d:0:0:0:A:A:0:0/128
    Container on A: f00d:0:0:0:A:A:0:1111/128

    Node B prefix:  f00d:0:0:0:B:B::/96
    Node B address: f00d:0:0:0:B:B:0:0/128
    Container on B: f00d:0:0:0:B:B:0:2222/128

IPv4 IP Address Assignment
--------------------------

Cilium will allocate IPv4 addresses to containers out of a ``/16`` node prefix.
This prefix can be specified with the ``--ipv4-range`` option.  If left
unspecified, Cilium will try and generate a unique prefix using the format
``10.X.0.0/16`` where X is replaced with the last byte of the first global
scope IPv4 address discovered on the node. This generated prefix is relatively
weak in uniqueness so it is highly recommended to always specify the IPv4
range.

The address ``10.X.0.1`` is reserved and represents the local node.

.. _arch_ip_connectivity:

********************
IP Interconnectivity
********************

When thinking about base IP connectivity with Cilium, its useful to consider
two different types of connectivity:

* Container-to-Container Connectivity

* Container Communication with External Hosts

Container-to-Container Connectivity
===================================

In the case of connectivity between two containers inside the same cluster,
Cilium is in full control over both ends of the connection. It can thus
transmit state and security context information between two container hosts by
embedding the information in encapsulation headers or even unused bits of the
IPv6 packet header. This allows Cilium to transmit the security context of
where the packet origins from which allows tracing back which container labels
are assigned to the origin container.

.. note::

   As the packet headers contain security sensitive information, it is higly
   recommended to either encrypt all traffic or run Cilium in a trusted network
   environment.

There are two possible approaches to performing network forwarding for
container-to-container traffic:

* **Overlay Routing:** In this mode, the network connecting the container
  hosts together does not need to be aware of the *node prefix* or the IP
  addresses of containers.  Instead, a *virtual overlay network* is created on
  top of the existing network infrastructure by creating tunnels between
  containers hosts using encapsulation protocols such as VXLAN, GRE, or Geneve.
  This minimizes the requirements on the underlying network infrastructure. The
  only requirement in this mode is for containers hosts to be able to reach
  each other by UDP (VXLAN/Geneve) or IP/GRE. As this requirement is typically
  already met in most environments, this mode usually does not require
  additional configuration from the user. Cilium can deterministically map from
  any container IP address to the corresponding node IP address, Cilium can
  look at the destination IP address of any packet destined to a container, and
  then use encapsulation to send the packet directly to the IP address of the
  node running that container. The destination node then decapsulates the
  packet, and delivers it to the local container.  Because overlay routing
  requires no configuration changes in the underlying network, it is often the
  easiest approach to adopt initially.

* **Direct Routing:**  In this mode, Cilium will hand all packets that are not
  addressed to a local container and not addressed to the local node to the
  Linux stack causing it to route the packet as it would route any other
  non-local packet. As a result, the network connecting the Linux node hosts
  must be aware that each of the node IP prefixes are reachable by using the
  node's primary IP address as an L3 next hop address.   In the case of a
  traditional physical network this would typically involve announcing each
  node prefix as a route using a routing protocol within the datacenter. Cloud
  providers (e.g, AWS VPC, or GCE Routes) provide APIs to achieve the same result.

Regardless of the option chosen, the container itself has no awareness of the
underlying network it runs on, it only contains a default route which points to
the IP address of the container host. Given the removal of the routing cache in
the Linux kernel, this reduces the amount of state to keep to the per
connection flow cache (TCP metrics) which allows to terminate millions of
connections in each container.

Container Communication with External Hosts
===========================================

Container communication with the outside world has two primary modes:

 * Containers exposing API services for consumption by hosts outside of the
   container cluster.

 * Containers making outgoing connections.  Examples include connecting to
   3rd-party API services like Twillio or Stripe as well as accessing private
   APIs that are hosted elsewhere in your enterprise datacenter or cloud
   deployment.

In the ''Direct Routing'' scenario described above, if container IP addresses
are routable outside of the container cluster, communication with external
hosts requires little more than enabling L3 forwarding on each of the Linux
nodes.

External Connectivity with Overlay Routing
==========================================

However, in the case of ''Overlay Routing'', accessing external hosts requires
additional configuration.

In the case of containers accepting inbound connections, such services are
likely exposed via some kind of load-balancing layer, where the load-balancer
has an external address that is not part of the Cilium network.  This can be
achieved by having a load-balancer container that both has a public IP on an
externally reachable network and a private IP on a Cilium network. However,
many container orchestration frameworks, like Kubernetes, have built in
abstractions to handle this "ingress" load-balancing capability, which achieve
the same effect that Cilium handles forwarding and security only for
''internal'' traffic between different services.

Containers that simply need to make outgoing connections to external hosts can
be addressed by configuring each Linux node host to masquerade connections from
containers to IP ranges other than the cluster prefix (IP masquerading is also
known as Network Address Port Translation, or NAPT).  This approach can be used
even if there is a mismatch between the IP version used for the container
prefix and the version used for Node IP addresses.

********
Security
********

Cilium provides security on multiple levels. Each can be used individually or
combined together.

* :ref:`arch_id_security`: Connectivity policies between endpoints (Layer 3),
  e.g. any endpoint with label `role=frontend` can connect to any endpoint with
  label `role=backend`.
* Restriction of accessible ports (Layer 4) for both incoming and outgoing
  connections, e.g. endpoint with label `role=frontend` can only make outgoing
  connections on port 443 (https) and endpoint `role=backend` can only accept
  connections on port 443 (https).
* Fine grained access control on application protocol level to secure HTTP and
  remote procedure call (RPC) protocols, e.g the endpoint with label
  `role=frontend` can only perform the REST API call `GET /userdata/[0-9]+`,
  all other API interactions with `role=backend` are restricted.

Currently on the roadmap, to be added soon:

* Authentication: Any endpoint which wants to initiate a connection to an
  endpoint with the label `role=backend` must have a particular security
  certificate to authenticate itself before being able to initiate any
  connections. See `GH issue 502
  <https://github.com/cilium/cilium/issues/502>`_ for additional details.
* Encryption: Communication between any endpoint with the label `role=frontend`
  to any endpoint with the label `role=backend` is automatically encrypted with
  a key that is automatically rotated. See `GH issue 504
  <https://github.com/cilium/cilium/issues/504>`_ to track progress on this
  feature.

.. _arch_id_security:
  
Identity based Connectivity Access Control
==========================================

Container management systems such as Kubernetes deploy a networking model which
assigns an individual IP address to each pod (group of containers). This
ensures simplicity in architecture, avoids unnecessary network address
translation (NAT) and provides each individual container with a full range of
port numbers to use. The logical consequence of this model is that depending on
the size of the cluster and total number of pods, the networking layer has to
manage a large number of IP addresses.

Traditionally security enforcement architectures have been based on IP address
filters.  Let's walk through a simple example: If all pods with the label
`role=frontend` should be allowed to initiate connections to all pods with the
label `role=backend` then each cluster node which runs at least one pod with
the label `role=backend` must have a corresponding filter installed which
allows all IP addresses of all `role=frontend` pods to initiate a connection to
the IP addresses of all local `role=backend` pods. All other connection
requests should be denied. This could look like this: If the destination
address is *10.1.1.2* then allow the connection only if the source address is
one of the following *[10.1.2.2,10.1.2.3,20.4.9.1]*.

Every time a new pod with the label `role=frontend` or `role=backend` is either
started or stopped, the rules on every cluster node which run any such pods
must be updated by either adding or removing the corresponding IP address from
the list of allowed IP addresses. In large distributed applications, this could
imply updating thousands of cluster nodes multiple times per second depending
on the churn rate of deployed pods. Worse, the starting of new `role=frontend`
pods must be delayed until all servers running `role=backend` pods have been
updated with the new security rules as otherwise connection attempts from the
new pod could be mistakenly dropped. This makes it difficult to scale
efficiently. 

In order to avoid these complications which can limit scalability and
flexibility, Cilium entirely separates security from network addressing.
Instead, security is based on the identity of a pod, which is derived through
labels.  This identity can be shared between pods. This means that when the
first `role=frontend` pod is started, Cilium assigns an identity to that pod
which is then allowed to initiate connections to the identity of the
`role=backend` pod. The subsequent start of additional `role=frontend` pods
only requires to resolve this identity via a key-value store, no action has to
be performed on any of the cluster nodes hosting `role=backend` pods. The
starting of a new pod must only be delayed until the identity of the pod has
been resolved which is a much simpler operation than updating the security
rules on all other cluster nodes.

.. image:: images/identity.png
    :align: center

What is an Endpoint Identity?
-----------------------------

The identity of an endpoint is derived based on the labels associated with the
pod or container. When a pod or container is started, Cilium will create an
endpoint based on the event received by the container runtime to represent the
pod or container on the network. As a next step, Cilium will resolve the
identity of the endpoint created. Whenever the labels of the pod or container
change, the identity is reconfirmed and automatically modified as required.

Not all labels associated with a container or pod are meaningful when deriving
the security identity. Labels may be used to store metadata such as the
timestamp when a container was launched. Cilium requires to know which labels
are meaningful and are subject to being considered when deriving the identity.
For this purpose, the user is required to specify a list of string prefixes of
meaningful labels. The standard behavior is to include all labels which start
with the prefix `id.`, e.g.  `id.service1`, `id.service2`,
`id.groupA.service44`. The list of meaningful label prefixes can be specified
when starting the cilium agent, see :ref:`admin_agent_options`.

.. _reserved_labels:

Special Identities
^^^^^^^^^^^^^^^^^^

All endpoints which are managed by Cilium will be assigned an identity. In
order to allow communication to network endpoints which are not managed by
Cilium, special identities exist to represent those. Special reserved
identities are prefixed with the string `reserved:`.

+---------------------+---------------------------------------------------+
| Identity            | Description                                       |
+---------------------+---------------------------------------------------+
| reserved:host       | The host network namespace on which the pod or    |
|                     | container is running.                             |
+---------------------+---------------------------------------------------+
| reserved:world      | Any network endpoint outside of the cluster       |
+---------------------+---------------------------------------------------+

TODO: Document `cidr:` identity once implemented.

Identity Management in the Cluster
----------------------------------

Identities are valid in the entire cluster which means that if several pods or
containers are started on several cluster nodes, all of them will resolve and
share a single identity if they share the identity relevant labels. This
requires coordination between cluster nodes.

.. image:: images/identity_store.png
    :align: center

The operation to resolve an endpoint identity is performed with the help of the
distributed key-value store which allows to perform atomic operations in the
form *generate a new unique identifier if the following value has not been seen
before*. This allows each cluster node to create the identity relevant subset
of labels and then query the key-value store to derive the identity. Depending
on whether the set of labels has been queried before, either a new identity
will be created, or the identity of the initial query will be returned.

Policy Enforcement
==================

All security policies are described assuming stateful policy enforcement for
session based protocols. This means that the intent of the policy is to
describe allowed direction of connection establishment. If the policy allows `A
=> B` then reply packets from `B` to `A` are automatically allowed as well.
However, `B` is not automatically allowed to initiate connections to `A`. If
that outcome is desired, then both directions must be explicitly allowed.

Security policies are primarily enforced at *ingress* which means that each
cluster node verifies all incoming packets and determines whether the packet is
allowed to be transmitted to the intended endpoint. Policy enforcement also
occurs at *egress* if required by the specific policy, e.g. a Layer 7 policy
restricting outgoing API calls.

Layer 3 policies are currently not enforced at *egress* to avoid the complexity
of resolving the destination endpoint identity before sending out the packet.
Instead, the identity of the source endpoint is embedded into the packet.

In order to enforce identity based security in a multi host cluster, the
identity of the transmitting endpoint is embedded into every network packet
that is transmitted in between cluster nodes. The receiving cluster node can
then extract the identity and verify whether a particular identity is allowed
to communicate with any of the local endpoints.

Default Security Policy
-----------------------

If no policy is loaded, the default behaviour is to allow all communication
unless policy enforcement has been explicitly enabled. As soon as the first
policy rule is loaded, policy enforcement is enabled automatically and any
communication must then be white listed or the relevant packets will be
dropped.

Similarly, if an endpoint is not subject to an *L4* policy, communication from
and to all ports is permitted. Associating at least one *L4* policy to an
endpoint will block all connectivity to ports unless explicitly allowed.


Orchestration System Specifics
==============================

Kubernetes
----------

Cilium regards each deployed Pod as an endpoint with regards to networking and
security policy enforcement. Labels associated with pods can be used to define
the identity of the endpoint.

When two pods communicate via a service construct, then the labels of the
origin pod apply to determine the identity.

Policy Language
===============

The security policy can be specified in the following formats:

* The Kubernetes *NetworkPolicy* specification which offers to configure a
  subset of the full Cilium security. For fun see `Kubernetes Network Policies
  <https://kubernetes.io/docs/concepts/services-networking/networkpolicies/>`_
  for details on how to configure Kubernetes network policies. It is possible
  to define base rules using the Kubernetes specification and then
  extend these using additional Cilium specific rules.
* The Cilium policy language as described below. In addition to the what the
  Kubernetes NetworkPolicy spec supports, the Cilium language allows to
  implement Layer 7 filtering, deny rules, and hierarchical rules for
  delegation and precedence purposes. Cilium also provides egress enforcement
  for Layer 4 and Layer 7 rules.

The data format used by the Cilium policy language is JSON. Additional formats
may be supported in the future.

Policy consists of a list of rules:

::

	{
		"rules": [{ rule1, rule2, rule3 }]
	}

.. _arch_rules:

Policy Rules
------------

Multiple types of policy rules are supported, all types following the simple
template:

* **coverage:** A list of labels which the endpoint must carry.
* **rule:** A type specific rule, the following rule types have been
  implemented:

  * **Allow/Requires:** Connectivity policy, e.g. allow a pod to talk to
    another pod
  * **L4** L4 connectivity policy

**Example:**

The following example describes a rule which applies to all endpoints which
carry the label `backend`. 

::

	[{
		"coverage": ["role=backend"],
		"allow": allowData
	}]

Allow Rules
-----------

This is the simplest rule type. The rule defines a list of labels which are
allowed to consume whatever endpoints are covered by the coverage.

If an endpoint transmits to another endpoint and the communication is not
permitted by at least one *allow* rule, all packets of the connection will be
dropped.

.. note:: Packet drops can be introspected by running the ``cilium monitor``
          tool which logs each dropped packet including metadata such as the
          reason (policy denied) and the source and destination identity.

+---------------+----------+---------------------------------------------------+
| Field         | Type     | Description                                       |
+---------------+----------+---------------------------------------------------+
| coverage      | Array of | List of labels that must match in order for this  |
|               | labels   | rule to be applied.                               |
+---------------+----------+---------------------------------------------------+
| allow         | Array of | List of labels which are allowed to initiate a    |
|               | allows   | connection to any endpoint covered by coverage.   |
+---------------+----------+---------------------------------------------------+

allow:

+---------------+----------+---------------------------------------------------+
| Field         | Type     | Description                                       |
+---------------+----------+---------------------------------------------------+
| action        | string   | { "accept", "always-accept", "deny" }             |
+---------------+----------+---------------------------------------------------+
| label         | label    | Allowed or denied label                           |
+---------------+----------+---------------------------------------------------+

A short form is available as alternative to the above verbose JSON syntax:

+---------------+----------+---------------------------------------------------+
| Field         | Type     | Description                                       |
+---------------+----------+---------------------------------------------------+
| coverage      | Array of | List of labels that must match in order for this  |
|               | strings  | rule to be applied.                               |
+---------------+----------+---------------------------------------------------+
| allow         | Array of | List of labels which are allowed to initiate a    |
|               | strings  | connection to any endpoint covered by coverage.   |
|               |          | The action is "accept" unless the label has the   |
|               |          | prefix `!` in which case the action is "deny".    |
+---------------+----------+---------------------------------------------------+

**Example:**

The following simple example using the form allows pods with the label
`role=frontend` to consume pods with the label `role=backend`:

::

	[{
		"coverage": ["role=backend"],
		"allow": ["role=frontend"]
	}]

The following example using the short form allows all pods with the label
`role=frontend` to consume pods with the label `role=backend` unless the
frontend pod carries the label `user=joe`:

::

	[{
		"coverage": ["role=backend"],
		"allow": ["role=frontend", "!user=joe"]
	}]

The special *always-accept* action is useful in combination with hierarchical
policy trees.  It allows to define *allow* rules which cannot be overruled by
child policy nodes. See :ref:`arch_tree_rules` for additional information on
policy tree and their precedence model.

The following example shows a child node `role`, which contains a rule that
disallows access from `role=frontend` to `role=backend`. However, the parent
node `root` allows access by using *always-accept*.

::

	{
		"name": "root",
		"rules": [{
                        "coverage": ["role=backend"],
                        "allow": [{
                                "action": "always-accept",
                                "label": { "key": "role=frontend" }
                        }]
                }],
                "children": {
                        "role": {
                                "rules": [{
                                        "coverage": ["role=backend"],
                                        "allow": ["!role=frontend"]
                                }]
                        }
                }
	}

Requires Rules
--------------

*Requires* rules define a list of additional labels that must
be present in the sending endpoint for an allow rule to take effect. A
*requires* rule itself does not grant permissions for consumption; It merely
imposes additional constraints. At least one *allow* rule is always required.

+---------------+----------+---------------------------------------------------+
| Field         | Type     | Description                                       |
+---------------+----------+---------------------------------------------------+
| coverage      | Array of | List of labels that must match in order for this  |
|               | labels   | rule to be applied.                               |
+---------------+----------+---------------------------------------------------+
| requires      | Array of | List of labels that must be present in any        |
|               | labels   | transmitting endpoint desiring to connect to any  |
|               |          | endpoint covered by coverage.                     |
+---------------+----------+---------------------------------------------------+

If an endpoint transmits to another endpoint and the communication is not
permitted because at least one of the required labels is not present, then the
applied behaviour would be the same as if it lacks an *allow* rule.

::

	[{
		"coverage": ["role=backend"],
		"allow": ["role=frontend"]
	},
	{
		"coverage": ["env=qa"],
		"requires": ["env=qa"]
	},
	{
		"coverage": ["env=prod"],
		"requires": ["env=prod"]
	}]

The example above extends the existing *allow* rule with two additional
*requires* rules. The first rule says that if an endpoint carries the label
`env=qa` then the consuming endpoint also needs to carry the label `env=qa`.
The second rule does the same for the label `env=prod`. The *requires* rules
allows for simple segmentation of existing rules into multiple environments
or groups.

Layer 4 Rules
-------------

The *L4* rule allows to impose Layer 4 restrictions on endpoints. It can be
applied to either incoming or outgoing connections. An *L4* by itself does not
allow communication, it must be combined with an *allow* rule to establish
basic connectivity.

+---------------+-----------+--------------------------------------------------+
| Field         | Type      | Description                                      |
+---------------+-----------+--------------------------------------------------+
| coverage      | Array of  | List of labels that must match in order for this |
|               | labels    | rule to be applied.                              |
+---------------+-----------+--------------------------------------------------+
| in-ports      | Array of  | Layer 4 policy for any incoming connection to an |
|               | l4-policy | endpoint covered by coverage.                    |
+---------------+-----------+--------------------------------------------------+
| out-ports     | Array of  | Layer 4 policy for any outgoing connection from  |
|               | l4-policy | an endpoint covered by coverage.                 |
+---------------+-----------+--------------------------------------------------+

**l4-policy:**

+---------------+-----------+--------------------------------------------------+
| Field         | Type      | Description                                      |
+---------------+-----------+--------------------------------------------------+
| port          | integer   | Allowed destination port                         |
+---------------+-----------+--------------------------------------------------+
| protocol      | string    | Allowed protocol {"tcp", "udp"} (optional)       |
+---------------+-----------+--------------------------------------------------+
| l7-parser     | string    | Name of Layer 7 parser. If set, causes traffic to|
|               |           | be inspected based on *rules*. (optional)        |
+---------------+-----------+--------------------------------------------------+
| l7-rules      | Array of  | Array of rules passed into Layer 7 parser        |
|               | string    | (optional). See :ref:`arch_l7_rules`             |
+---------------+-----------+--------------------------------------------------+

The following example shows how to restrict Layer 4 communication of any
endpoint carrying the label `role=frontend` and restrict incoming connections
to TCP on port 80 or port 443. Outgoing connections must also be TCP and are
restricted to port 8080.

::

	[{
		"coverage": ["role=frontend"],
		"l4": [{
			"in-ports": [
                                { "port": 80, "protocol": "tcp" },
                                { "port": 443, "protocol": "tcp" }
                        ],
			"out-ports": [{
                                "port": 8080, "protocol": "tcp"
                        }]
		}]
	}]

.. _arch_l7_rules:

Layer 7 Rules
-------------

Layer 7 rules are currently limited to IPv4. Policies can be applied for both
incoming and outgoing requests. The enforcement point is defined by the
location of the rules in either the "in-ports" or "out-ports" field of the
Layer 4 policy rule.

Unlike Layer 3 and Layer 4 policies, violation of Layer 7 rules does not result
in packet drops. Instead, if possible, an access denied message such as an
*HTTP 403 access denied* is sent back to the sending endpoint.

TODO: describe rules

.. _arch_tree_rules:

Hierarchical Rules
------------------

In order to allow implementing precedence and priority of rules. Policy rules
can be organized in the form of a tree. This tree consists of policy nodes
based on the following definition:

Name : string (optional)
    Relative name of the policy node. If omitted, then "root" is assumed and
    rules belong to the root node. Must be unique across all siblings 
    attached to the same parent.
Rules : array of rules
    List of rules, see :ref:`arch_rules`
Children:  Map with node entries (optional)
    Map holding children policy nodes. The name of each child policy node is
    prefixed with the name of its parent policy node using a `.` delimiter,
    e.g. a node `child` attached to the root node will have the absolute name
    `root.child`.

::

	{
                "name": "root",
		"rules": [{ rule1, rule2, rule3 }]
                "children": {
                        "child1": {
                                "rules": [{ rule1, rule2, rule3 }]
                        },
                        "child2": {
                                "rules": [{ rule1, rule2, rule3 }]
                        }
                }
	}

Automatic coverage of child nodes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A key property of child policy nodes is that their name implies an implicit
*coverage*. The absolute name of the policy node with the `root` prefix
omitted acts as an implicit coverage which is applied to all rules of the node.

**Example:**
A node `k8s` which is attached to the node `io` will have the absolute name
`root.io.k8s`. Rules of the node will only apply if the endpoint in question
carries a label which starts with the prefix `io.k8s`.

Additionally, any rules of a child node may only cover labels that share the
prefix of the absolute node path. This means that a child `id.foo` cannot
contain a rule which covers the label `id.bar.example`, but it can contain a
rule that covers the label `id.foo.example`.

Unlike an arbitrary label selector attached to each node, this property ensures
that a parent node always covers all endpoints of all its children, which is
essential to keep  precedence rules simple as described in the next section.

Precedence Rules
^^^^^^^^^^^^^^^^

1. Within a single policy node, a deny rule always overwrites any conflicting
   allow rules. If a label is both denied and allowed, it will always be
   denied.
2. If a node allows a label and a child node later denies the label then the
   label will be denied unless the allow rule is a *always-accept* rule in which
   case the parent always takes precedence.

Merging of Nodes
^^^^^^^^^^^^^^^^

TODO

Policy Repository
=================

Policy rules imported into the Cilium agent are not shared with other compute
nodes and are only enforced within the boundaries of the compute node. In order
to enforce security policies across an entire cluster, one of the following
options can be applied to distribute security policies across all cluster
nodes:

* Use of Kubernetes NetworkPolicy objects to define the policy. NetworkPolicy
  objects are automatically distributed to all worker nodes and the Cilium
  agent will import them automatically. (TODO: Describe option to use
  third-party objects to distribute native Cilium policy).
* Use of a configuration management system such as chef, puppet, ansible,
  cfengine to automatically import a policy into all agents. (TODO: link to
  guide as soon as one exists.)
* Use of a git tree to maintain the policy in combination with a post-merge
  hook which automatically imports the policy. (TODO: Write & link to guide)
* Use of a distributed filesystem shared across all cluster node in combination
  with a filesystem watcher that invokes `cilium import` upon detection of any
  change.

************************************
Integration with Container Platforms
************************************

Cilium is deeply integrated with container platforms like Docker or Kubernetes.
This enables Cilium to perform network forwarding and security using a model
that maps direction to notions of identity (e.g., labels) and service
abstractions that are native to the container platform.

In this section, we will provide more detail on how Cilium integrates with
Docker and Kubernetes.

Docker Integration
^^^^^^^^^^^^^^^^^^

Docker supports network plugins via the `libnetwork plugin interface
<https://github.com/docker/libnetwork/blob/master/docs/design.md>`_ .

When using Cilium with Docker, one creates a single logical Docker network of
type `cilium` and with an IPAM-driver of type `cilium`, which delegates
control over IP address management and network connectivity to Cilium for all
containers attached to this network for both IPv4 and IPv6 connectivity.  Each
Docker container gets an IP address from the node prefix of the node running
the container.

When deployed with Docker, each Linux node runs a `cilium-docker` agent,
which receives libnetwork calls from Docker and then communicates with the
Cilium Agent to control container networking.

Security policies controlling connectivity between the Docker containers can be
written in terms of the Docker container labels passed to Docker while creating
the container.  These policies can be created/updated via communication
directly with the Cilium agent, either via API or by using the Cilium CLI
client.

Kubernetes Integration
^^^^^^^^^^^^^^^^^^^^^^

When deployed with Kubernetes, Cilium provides four core Kubernetes networking
capabilities:

* Direct pod-to-pod network inter-connectivity.
* Service-based load-balancing for pod-to-pod inter-connectivity (i.e., a
  kube-proxy replacement).
* Identity-based security policies for all  (direct and service-based)
  Pod-to-Pod inter-connectivity.
* External-to-Pod service-based load-balancing (referred to as `Ingress` in
  Kubernetes)

The Kubernetes documentation contains more background on the `Kubernetes
Networking Model
<https://kubernetes.io/docs/concepts/cluster-administration/networking/>`_ and
`Kubernetes Network Plugins
<https://kubernetes.io/docs/concepts/cluster-administration/network-plugins/>`_
.

Direct Pod-to-Pod Connectivity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In Kubernetes, containers are deployed within units referred to as Pods, which
include one or more containers reachable via a single IP address.  With Cilium,
each Pod gets an IP address from the node prefix of the Linux node running the
Pod.   In the absence of any network security policies, all Pods can reach each
other.

Pod IP addresses are typically local to the Kubernetes cluster.  If pods need
to reach services outside the cluster as a client, the Kubernetes nodes are
typically configured to IP masquerade all traffic sent from containers to
external prefix.

Pod-to-Pod Service-based Load-balancing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Kubernetes has developed the Services abstraction which provides the user the
ability to load balance network traffic to different pods. This abstraction
allows the pods reaching out to other pods by a single IP address, a virtual IP
address, without knowing all the pods that are running that particular service.

Without Cilium, kube-proxy is installed on every node, watches for endpoints
and services addition and removal on the kube-master which allows it to to
apply the necessary enforcement on iptables. Thus, the received and sent
traffic from and to the pods are properly routed to the node and port serving
for that service. For more information you can check out the kubernetes user
guide for `Services  <http://kubernetes.io/docs/user-guide/services>`__.

Cilium loadbalancer acts on the same principles as kube-proxy, it watches for
services addition or removal, but instead of doing the enforcement on the
iptables, it updates BPF map entries on each node. For more information, see
the `Pull Request <https://github.com/cilium/cilium/pull/109>`__.

TODO: describe benefits of BPF based load-balancer compared to kube-proxy
      iptables

External-to-Pod Service-based Load-balancing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TODO: Verify this

Kubernetes supports an abstraction known as `Ingress
<https://kubernetes.io/docs/user-guide/ingress/#what-is-ingress>`_ that allows
a Pod-based Kubernetes service to expose itself for access outside of the
cluster in a load-balanced way.  In a typical setup, the external traffic would
be sent to a publicly reachable IP + port on the host running the Kubernetes
master, and then be load-balanced to the pods implementing the current service
within the cluster.

Cilium supports Ingress with TCP-based load-balancing.  Moreover, it supports
''direct server return'', meaning that reply traffic from the pod to the
external client is sent directly, without needing to pass through the
kubernetes master host.

TODO: insert graphic showing LB + DSR.


