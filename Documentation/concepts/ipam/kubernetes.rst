.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

#####################
Kubernetes Host Scope
#####################

The Kubernetes host-scope IPAM mode delegates the address allocation to each
individual node in the cluster. IPs are allocated out of the ``PodCIDR`` range
associated to each node by Kubernetes.

In this mode, the Cilium agent will wait on startup until the ``PodCIDR`` range
is made available via the Kubernetes ``v1.Node`` object for all enabled address
families via one of the following methods:

**via v1.Node resource field**

==================== ============================================================
Field                Description
==================== ============================================================
``Spec.PodCIDRs``    IPv4 and/or IPv6 PodCIDR range
``Spec.PodCIDR``     IPv4 or IPv6 PodCIDR range
==================== ============================================================

.. note:: It is important to run the ``kube-controller-manager`` with the flag
	  ``--allocate-node-cidrs`` flag to indicate to Kubernetes that PodCIDR
	  ranges should be allocated.

**via v1.Node annotation**

=================================== ============================================================
Annotation                          Description
=================================== ============================================================
``io.cilium.network.ipv4-pod-cidr`` IPv4 PodCIDR range
``io.cilium.network.ipv6-pod-cidr`` IPv6 PodCIDR range
=================================== ============================================================

.. note:: The annotation-based mechanism is primarily useful in combination with
	  older Kubernetes versions which do not support ``Spec.PodCIDRs`` yet
	  but support for both IPv4 and IPv6 is enabled.
