.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _concepts_masquerading:

Masquerading
============

IPv4 addresses used for pods are typically allocated from RFC1918 private
address blocks and thus, not publicly routable. Cilium will automatically
masquerade the source IP address of all traffic that is leaving the cluster to
the IPv4 address of the node as the node's IP address is already routable on
the network.

.. image:: masquerade.png
    :align: center

This behavior can be disabled with the option ``masquerade: false`` in which
case no masquerading will be performed.

Configuration
-------------

Setting the routable CIDR
  The default behavior is to exclude any destination within the IP allocation
  CIDR of the local node. If the pod IPs are routable across a wider network,
  that network can be specified with the option: ``native-routing-cidr:
  10.0.0.0/8`` in which case all destinations within that CIDR will **not** be
  masqueraded.

Setting the masquerading interface
  The default behavior will masquerade all traffic leaving on a non-Cilium
  network device. This typically leads to the correct behavior. In order to
  limit the network interface on which masquerading should be performed, the
  option ``egress-masquerade-interfaces: eth0`` can be used.

  .. note::

     It is possible to specify an interface prefix as well, by specifying
     ``eth+``, all interfaces matching the prefix ``eth`` will be used for
     masquerading.

  This setting is only available in iptables-based mode (see
  :ref:`masq_modes`).

.. _masq_modes:

Implementation Modes
--------------------

eBPF-based
  The eBPF-based implementation is the most efficient
  implementation. It requires Linux kernel 4.19 and can be enabled with the
  option ``enable-bpf-masquerade: true``.

iptables-based
  This is the legacy implementation that will work on all kernel versions.
