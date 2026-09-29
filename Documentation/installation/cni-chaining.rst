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

.. note::

   When using CNI chaining with :ref:`encryption_wg`,
   :ref:`encryption_ipsec` (if supported by the chaining mode), or
   :ref:`egress-gateway` with a gateway on another node, set the Helm option
   ``cni.enableRouteMTUForCNIChaining`` to ``true``. This makes Cilium
   account for encryption or tunneling overhead in Pod route MTUs and helps
   avoid packet fragmentation. Egress Gateway can tunnel traffic even when
   native routing is enabled.

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
