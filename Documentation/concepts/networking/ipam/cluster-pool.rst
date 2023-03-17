.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _ipam_crd_cluster_pool:

#######################
Cluster Scope (Default)
#######################

The cluster-scope IPAM mode assigns per-node PodCIDRs to each node and
allocates IPs using a host-scope allocator on each node. It is thus similar to
the :ref:`k8s_hostscope` mode. The difference is that instead of Kubernetes
assigning the per-node PodCIDRs via the Kubernetes ``v1.Node`` resource, the
Cilium operator will manage the per-node PodCIDRs via the ``v2.CiliumNode``
resource. The advantage of this mode is that it does not depend on Kubernetes
being configured to hand out per-node PodCIDRs.

************
Architecture
************

.. image:: cluster_pool.png
    :align: center

This is useful if Kubernetes cannot be configured to hand out PodCIDRs or if
more control is needed.

In this mode, the Cilium agent will wait on startup until the ``podCIDRs`` range
are made available via the Cilium Node ``v2.CiliumNode`` object for all enabled
address families via the resource field set in the ``v2.CiliumNode``:

====================== ==============================
Field                  Description
====================== ==============================
``spec.ipam.podCIDRs`` IPv4 and/or IPv6 PodCIDR range
====================== ==============================

*************
Configuration
*************

For a practical tutorial on how to enable this mode in Cilium, see
:ref:`gsg_ipam_crd_cluster_pool`.

***************
Troubleshooting
***************

Look for allocation errors
==========================

Check the ``Error`` field in the ``status.ipam.operator-status`` field:

.. code-block:: shell-session

    kubectl get ciliumnodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.ipam.operator-status}{"\n"}{end}'
    
Check for conflicting node CIDRs
================================

``10.0.0.0/8`` is the default pod CIDR. If your node network is in the same range
you will lose connectivity to other nodes. All egress traffic will be assumed
to target pods on a given node rather than other nodes.

You can solve it in two ways:

  - Explicitly set ``clusterPoolIPv4PodCIDRList`` to a non-conflicting CIDR
  - Use a different CIDR for your nodes

**********************
Cluster Pool v2 (Beta)
**********************

Cluster Pool v2 (Beta) extends the above mechanism to allow additional PodCIDRs
to be dynamically allocated to each node based on usage. With v2, each Cilium
agent instance reports the utilization of its PodCIDRs via the ``CiliumNode``
resource.

If a node is running low on available pod IPs, the operator will assign an
additional PodCIDR to that node. Likewise, if a node has unused PodCIDRs, it
will eventually release it, allowing the operator to re-assign the released
PodCIDR to a different node if needed.

When running v2, the ``CiliumNode`` resource is extended with an additional
PodCIDR status section:

+-------------------------+----------------------------------------------------+
|Field                    | Description                                        |
+=========================+====================================================+
|``spec.ipam.podCIDRs``   | List of assigned IPv4 and/or IPv6 PodCIDRs         |
+-------------------------+----------------------------------------------------+
|``status.ipam.pod-cidrs``| PodCIDR utilization                                |
|                         | (one of: ``in-use``, ``depleted``, or ``released``)|
+-------------------------+----------------------------------------------------+

The operator assigns a new PodCIDR to a node if all of its PodCIDRs are either
depleted or released.

Limitations
===========

Cluster Pool v2 is a preview feature. The following limitations currently apply
to Cilium running in ``cluster-pool-v2beta`` IPAM mode:

.. warning::
  - Tunnel mode is not supported. Cluster Pool v2 may only be used in direct
    routing mode.
  - Transparent encryption with IPSec is not supported.

The current status of these limitations is tracked in :gh-issue:`18987`.

Configuration
=============

To enable Cluster Pool v2, pass ``--set ipam.mode=cluster-pool-v2beta`` to your
Helm options. The CIDR pool used in Cluster Pool v2 mode are configured the same
way as regular cluster pool (see :ref:`gsg_ipam_crd_cluster_pool`).

In addition, the thresholds for when a PodCIDR should be allocated or released
can be configured per node via the following ``CiliumNode.spec.ipam`` fields:

``spec.ipam.pod-cidr-allocation-threshold``
  Defines the minimum number of free IPs which must be available to this node
  via its PodCIDR pool.

  If the total number of IP addresses in the PodCIDR pool is less than this
  value, the PodCIDRs currently in-use by this node will be marked as depleted
  and Cilium operator will allocate a new PodCIDR to this node.

  This value effectively defines the buffer of IP addresses available
  immediately without requiring  Cilium operator to get involved.

  If unspecified, defaults to 8.


``spec.ipam.pod-cidr-release-threshold``
  Defines the maximum number of free IPs which may be available to this node via
  its PodCIDR pool.

  While the total number of free IP addresses in the PodCIDR pool is larger than
  this value, Cilium agent will attempt to release currently unused PodCIDR.

  If unspecified, defaults to 16.
