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

For IPv6 addresses masquerading is performed only when using iptables
implementation mode.

This behavior can be disabled with the option ``enable-ipv4-masquerade: false``
for IPv4 and ``enable-ipv6-masquerade: false`` for IPv6 traffic leaving the host.

Configuration
-------------

Setting the routable CIDR
  The default behavior is to exclude any destination within the IP allocation
  CIDR of the local node. If the pod IPs are routable across a wider network,
  that network can be specified with the option: ``ipv4-native-routing-cidr:
  10.0.0.0/8`` (or ``ipv6-native-routing-cidr: fd00::/100`` for IPv6 addresses)
  in which case all destinations within that CIDR will **not** be masqueraded.

Setting the masquerading interface
  See :ref:`masq_modes` for configuring the masquerading interfaces.

.. _masq_modes:

Implementation Modes
--------------------

eBPF-based
**********

The eBPF-based implementation is the most efficient
implementation. It requires Linux kernel 4.19 and can be enabled with
the ``bpf.masquerade=true`` helm option.

The current implementation depends on :ref:`the BPF NodePort feature <kubeproxy-free>`.
The dependency will be removed in the future (:gh-issue:`13732`).

Masquerading can take place only on those devices which run the eBPF masquerading
program. This means that a packet sent from a pod to an outside address will be
masqueraded (to an output device IPv4 address), if the output device runs the program.
If not specified, the program will be automatically attached to the devices selected by
:ref:`the BPF NodePort device detection mechanism <Nodeport Devices>`.
To manually change this, use the ``devices`` helm option. Use ``cilium status``
to determine which devices the program is running on:

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium status | grep Masquerading
    Masquerading:   BPF (ip-masq-agent)   [eth0, eth1]  10.0.0.0/16

From the output above, the program is running on the ``eth0`` and ``eth1`` devices.


The eBPF-based masquerading can masquerade packets of the following IPv4 L4 protocols:

- TCP
- UDP
- ICMP

.. note::

    For ICMP, support is limited to Echo request, Echo reply, and the
    error message "Destination unreachable, fragmentation required,
    and DF flag set".

By default, all packets from a pod destined to an IP address outside of the
``ipv4-native-routing-cidr`` range are masqueraded, except for packets destined
to other cluster nodes. The exclusion CIDR is shown in the above output of
``cilium status`` (``10.0.0.0/16``).

.. note::

    When eBPF-masquerading is enabled, traffic from pods to the External IP of
    cluster nodes will also not be masqueraded. The eBPF implementation differs
    from the iptables-based masquerading on that aspect. This limitation is
    tracked at :gh-issue:`17177`.

To allow more fine-grained control, Cilium implements `ip-masq-agent
<https://github.com/kubernetes-sigs/ip-masq-agent>`_ in eBPF which can be
enabled with the ``ipMasqAgent.enabled=true`` helm option.

The eBPF-based ip-masq-agent supports the ``nonMasqueradeCIDRs`` and
``masqLinkLocal`` options set in a configuration file. A packet sent from a pod to
a destination which belongs to any CIDR from the ``nonMasqueradeCIDRs`` is not
going to be masqueraded. If the configuration file is empty, the agent will provision
the following non-masquerade CIDRs:

- ``10.0.0.0/8``
- ``172.16.0.0/12``
- ``192.168.0.0/16``
- ``100.64.0.0/10``
- ``192.0.0.0/24``
- ``192.0.2.0/24``
- ``192.88.99.0/24``
- ``198.18.0.0/15``
- ``198.51.100.0/24``
- ``203.0.113.0/24``
- ``240.0.0.0/4``

In addition, if the ``masqLinkLocal`` is not set or set to false, then
``169.254.0.0/16`` is appended to the non-masquerade CIDRs list.

The agent uses Fsnotify to track updates to the configuration file, so the original
``resyncInterval`` option is unnecessary.

The example below shows how to configure the agent via :term:`ConfigMap` and to verify it:

.. literalinclude:: ../../../examples/kubernetes-ip-masq-agent/rfc1918.yaml

.. parsed-literal::

    $ kubectl create -n kube-system -f \ |SCM_WEB|\/examples/kubernetes-ip-masq-agent/rfc1918.yaml

    $ # Wait ~60s until the ConfigMap is propagated into the configuration file

    $ kubectl -n kube-system exec ds/cilium -- cilium bpf ipmasq list
    IP PREFIX/ADDRESS
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16

Alternatively, you can pass ``--set ipMasqAgent.config.nonMasqueradeCIDRs='{10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}'``
and ``--set ipMasqAgent.config.masqLinkLocal=false`` when installing Cilium via Helm to
configure the ``ip-masq-agent`` as above.

.. note::

    eBPF based masquerading is currently not supported for IPv6 traffic.

iptables-based
**************

This is the legacy implementation that will work on all kernel versions.

The default behavior will masquerade all traffic leaving on a non-Cilium
network device. This typically leads to the correct behavior. In order to
limit the network interface on which masquerading should be performed, the
option ``egress-masquerade-interfaces: eth0`` can be used.

.. note::

   It is possible to specify an interface prefix as well, by specifying
   ``eth+``, all interfaces matching the prefix ``eth`` will be used for
   masquerading.
