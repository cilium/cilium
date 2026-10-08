.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _cni_chaining:

************
CNI Chaining
************

CNI chaining allows to use Cilium in combination with other CNI plugins.

With Cilium CNI chaining, the base network connectivity and IP address management
is managed by the non-Cilium CNI plugin, but Cilium attaches eBPF programs to the
network devices created by the non-Cilium plugin to provide L3/L4 network
visibility, policy enforcement and other advanced features.

Route MTU
=========

When a Cilium feature adds encapsulation to Pod traffic, the route MTU inside
the Pod must account for that overhead. This applies to WireGuard encryption
and to traffic redirected through an egress gateway, not only to the
encapsulation configured by the primary CNI plugin.

Cilium automatically configures the route MTU in chained Pods. This avoids
fragmentation when the effective datapath MTU is reduced by encapsulation.

IPsec also adds encapsulation overhead, but IPsec with CNI chaining is
currently unsupported; see :ref:`encryption_ipsec` for its limitations.
Enabling this option does not remove those limitations.

CNI plugins
===========

.. toctree::
   :maxdepth: 1
   :glob:

   cni-chaining-aws-cni
   cni-chaining-azure-cni
   cni-chaining-calico
   cni-chaining-generic-veth
   cni-chaining-oracle-oke
   cni-chaining-portmap
   cni-chaining-weave
