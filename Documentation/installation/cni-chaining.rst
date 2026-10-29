.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _cni_chaining:

************
CNI Chaining
************

CNI chaining allows you to use Cilium in combination with other CNI plugins.

With Cilium CNI chaining, the base network connectivity and IP address management
is managed by the non-Cilium CNI plugin, but Cilium attaches eBPF programs to the
network devices created by the non-Cilium plugin to provide L3/L4 network
visibility, policy enforcement and other advanced features.

.. _cni_chaining_mtu:

MTU
===

By default, Cilium does not adjust the MTU of the Pods when chaining, so Pods
use the MTU configured by the other CNI plugins. Features that add encapsulation
or encryption overhead on top of Pod traffic are therefore not accounted for,
and the resulting packets might get fragmented, which can lead to a network
performance degradation.

Set the Helm option ``cni.enableRouteMTUForCNIChaining`` to ``true`` to make
Cilium set a route MTU for Pods that accounts for such overhead. This is
required when using any of the following features:

* :ref:`WireGuard encryption <encryption_wg>`
* :ref:`Egress Gateway <egress-gateway>`
* :ref:`Tunneling <encapsulation>` (``routingMode=tunnel``)

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
