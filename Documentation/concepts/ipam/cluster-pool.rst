.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _ipam_crd_cluster_pool:

#######################
Cluster Scope (Default)
#######################

Cilium Cluster-pool IPAM is based on Kubernetes host-scope IPAM, for more info
see :ref:`k8s_hostscope`. The functionality is the same but the ``PodCIDRs`` are
allocated and managed entirely by Cilium Operator.

In this mode, the Cilium agent will wait on startup until the ``PodCIDRs`` range
are made available via the Cilium Node ``v2.CiliumNode`` object for all enabled
address families via the resource field set in the ``v2.CiliumNode``:

====================== ==============================
Field                  Description
====================== ==============================
``Spec.IPAM.PodCIDRs`` IPv4 and/or IPv6 PodCIDR range
====================== ==============================

If Cilium Operator can not allocate ``PodCIDRs`` for that node it will keep
a status message in ``Status.Operator.Error``.
