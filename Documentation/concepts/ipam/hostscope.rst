.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _ipam_hostscope:

####################
Host Scope (Legacy)
####################

.. note::

   The hostscope IPAM mode has been deprecated and will be removed in Cilium
   1.10. Please switch to one of the other modes such as Kubernetes Host Scope
   or the Cluster Scope mode.

The host-scope IPAM mode delegates the address allocation to each individual
node in the cluster. Each cluster node is assigned an allocation CIDR out of
which the node can allocate IPs without further coordination with any other
nodes. For details on running the hostscope IPAM mode in the context of
Kubernetes, please see :ref:`k8s_hostscope`.

This means that no state needs to be synchronized between cluster nodes to
allocate IP addresses and to determine whether an IP address belongs to an
*endpoint* of the cluster and whether that *endpoint* resides on the local
cluster node.

**************
Default Values
**************

The following values are used by default if the cluster prefix is left
unspecified. These are meant for testing and need to be adjusted according to
the needs of your environment.

.. note:: Relying default values via automatically generated per node PodCIDRs
          is discouraged in any production environment. It can result in IPAM
          conflicts and undesired renumbering if the IPAM state on a node is
          lost for some reason.

+-------+----------------+--------------------------------------------------+
| Type  | Cluster        | Node Prefix                                      |
+-------+----------------+--------------------------------------------------+
| IPv4  | ``10.0.0.0/8`` | ``10.X.0.0/16`` where ``X`` is derived using the |
|       |                | last 8 bits of the first IPv4 address in the list|
|       |                | of global scope addresses on the cluster node.   |
+-------+----------------+--------------------------------------------------+
| IPv6  | ``f00d::/48``  | ``f00d:0:0:0:<ipv4-address>::/96`` where the     |
|       |                | IPv4 address is the first address in the list of |
|       |                | global scope addresses on the cluster node.      |
|       |                |                                                  |
|       |                | Note: Only 16 bits out of the ``/96`` node       |
|       |                | prefix are currently used when allocating        |
|       |                | container addresses. This allows to use the      |
|       |                | remaining 16 bits to store arbitrary connection  |
|       |                | state when sending packets between nodes. A      |
|       |                | typical use case for the state is direct server  |
|       |                | return.                                          |
+-------+----------------+--------------------------------------------------+

The size of the IPv4 cluster prefix can be changed with the
``--ipv4-cluster-cidr-mask-size`` option. The size of the IPv6 cluster prefix
is currently fixed sized at ``/48``. The node allocation prefixes can be
specified manually with the option ``--ipv4-range`` respectively
``--ipv6-range``.
