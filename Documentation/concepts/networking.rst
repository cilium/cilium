.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _arch_ip_connectivity:
.. _multi host networking:

*********************
Multi Host Networking
*********************

Cilium is in full control over both ends of the connection for connections
inside the cluster. It can thus transmit state and security context information
between two container hosts by embedding the information in encapsulation
headers or even unused bits of the IPv6 packet header. This allows Cilium to
transmit the security context of where the packet originates, which allows
tracing back which container labels are assigned to the origin container.

.. note::

   As the packet headers contain security sensitive information, it is highly
   recommended to either encrypt all traffic or run Cilium in a trusted network
   environment.

Cilium keeps the networking concept as simple as possible. There are two
networking models to choose from.

- :ref:`arch_overlay`
- :ref:`arch_direct_routing`

Regardless of the option chosen, the container itself has no awareness of the
underlying network it runs on; it only contains a default route which points to
the IP address of the cluster node. Given the removal of the routing cache in
the Linux kernel, this reduces the amount of state to keep in the per
connection flow cache (TCP metrics), which allows to terminate millions of
connections in each container.

.. _arch_overlay:

Overlay Network Mode
====================

When no configuration is provided, Cilium automatically runs in this mode.

In this mode, all cluster nodes form a mesh of tunnels using the UDP based
encapsulation protocols `VXLAN` or `Geneve`. All container-to-container network
traffic is routed through these tunnels. This mode has several major
advantages:

- **Simplicity:** The network which connects the cluster nodes does not need to
  be made aware of the *cluster prefix*. Cluster nodes can spawn multiple
  routing or link-layer domains. The topology of the underlying network is
  irrelevant as long as cluster nodes can reach each other using IP/UDP.

- **Auto-configuration:** When running together with an orchestration system
  such as Kubernetes, the list of all nodes in the cluster including their
  associated allocation prefix node is made available to each agent
  automatically. This means that if Kubernetes is being run with the
  ``--allocate-node-cidrs`` option, Cilium can form an overlay network
  automatically without any configuration by the user. New nodes joining the
  cluster will automatically be incorporated into the mesh.

- **Identity transfer:** Encapsulation protocols allow for the carrying of
  arbitrary metadata along with the network packet. Cilium makes use of this
  ability to transfer metadata such as the source security identity and
  load balancing state to perform direct-server-return.

.. _arch_direct_routing:

Direct / Native Routing Mode
============================

.. note:: This is an advanced networking mode which requires the underlying
          network to be made aware of container IPs. You can enable this mode
          by running Cilium with the option ``--tunnel disabled``.

In direct routing mode, Cilium will hand all packets which are not addressed
for another local endpoint to the routing subsystem of the Linux kernel. This
means that the packet will be routed as if a local process would have emitted
the packet. As a result, the network connecting the cluster nodes must be aware
that each of the node IP prefixes are reachable by using the node's primary IP
address as an L3 next hop address.

Cilium automatically enables IP forwarding in Linux when direct mode is
configured, but it is up to the container cluster administrator to ensure that
each routing element in the underlying network has a route that describes each
node IP as the IP next hop for the corresponding node prefix.

This is typically achieved using two methods:

- Operation of a routing protocol such as OSPF or BGP via routing daemon such
  as Zebra, bird, bgpd. The routing protocols will announce the *node allocation
  prefix* via the node's IP to all other nodes.

- Use of the cloud provider's routing functionality. Refer to the documentation
  of your cloud provider for additional details  (e.g,. `AWS VPC Route Tables`_
  or `GCE Routes`_). These APIs can be used to associate each node prefix with
  the appropriate next hop IP each time a container node is added to the
  cluster.  If you are running Kubernetes with the ``--cloud-provider`` in
  combination with the ``--allocate-node-cidrs`` option then this is configured
  automatically for IPv4 prefixes.

.. note:: Use of direct routing mode with advanced policy use cases such as
          L7 policies is currently beta. Please provide feedback and file a
          GitHub issue if you experience any problems.


.. _AWS VPC Route Tables: http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Route_Tables.html
.. _GCE Routes: https://cloud.google.com/compute/docs/reference/latest/routes

There are two possible approaches to performing network forwarding for
container-to-container traffic:

.. _Cluster Mesh:

Cluster Mesh
============

Cluster mesh extends the networking datapath across multiple clusters. It
allows endpoints in all connected clusters to communicate while providing full
policy enforcement. Load-balancing is available via Kubernetes annotations.

See :ref:`gs_clustermesh` for instructions on how to set up cluster mesh.

Container Communication with External Hosts
===========================================

Container communication with the outside world has two primary modes:

 * Containers exposing API services for consumption by hosts outside of the
   container cluster.

 * Containers making outgoing connections.  Examples include connecting to
   3rd-party API services like Twilio or Stripe as well as accessing private
   APIs that are hosted elsewhere in your enterprise datacenter or cloud
   deployment.

In the :ref:`arch_direct_routing` mode described before, if container IP
addresses are routable outside of the container cluster, communication with
external hosts requires little more than enabling L3 forwarding on each of the
Linux nodes.

.. _concepts_external_access:

External Network Connectivity
=============================

If the destination of a packet lies outside of the cluster, Cilium will
delegate routing to the routing subsystem of the cluster node to use the
default route which is installed on the node of the cluster.

As the IP addresses used for the **cluster prefix** are typically allocated
from RFC1918 private address blocks and are not publicly routable. Cilium will
automatically masquerade the source IP address of all traffic that is leaving
the cluster. This behavior can be disabled by running ``cilium-agent`` with
the option ``--masquerade=false``.

Public Endpoint Exposure
========================

In direct routing mode, *endpoint* IPs can be publicly routable IPs and no
additional action needs to be taken.

In overlay mode, *endpoints* that are accepting inbound connections from
cluster external clients likely want to be exposed via some kind of
load-balancing layer. Such a load-balancer will have a public external address
that is not part of the Cilium network.  This can be achieved by having a
load-balancer container that both has a public IP on an externally reachable
network and a private IP on a Cilium network.  However, many container
orchestration frameworks, like Kubernetes, have built in abstractions to handle
this "ingress" load-balancing capability, which achieve the same effect that
Cilium handles forwarding and security only for ''internal'' traffic between
different services.

