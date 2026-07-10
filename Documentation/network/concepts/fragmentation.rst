.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _concepts_fragmentation:

Fragment Handling
=================

By default, Cilium configures the eBPF datapath to perform IP fragment tracking
to allow protocols that do not support segmentation (such as UDP) to
transparently transmit large messages over the network. This feature may be
configured using the following options:

- ``--enable-ipv4-fragment-tracking``: Enable or disable IPv4 fragment
  tracking. Enabled by default.
- ``--enable-ipv6-fragment-tracking``: Enable or disable IPv6 fragment
  tracking. Enabled by default.
- ``--bpf-fragments-map-max``: Control the maximum number of active concurrent
  connections using IP fragmentation. For the defaults, see `bpf_map_limitations`.

To check whether fragmentation occurred, check the value of the following metrics:

- ``cilium_bpf_map_pressure{map_name="cilium_ipv4_frag_datagrams"}``
- ``cilium_bpf_map_pressure{map_name="cilium_ipv6_frag_datagrams"}``

If they're non-zero, it means that fragmented packets were processed.

As well, it's possible check how many MTU error messages (i.e. ICMP ``fragmentation_needed`` or ICMPv6 ``packet_too_big``)
have been processed by Cilium's datapath by checking the following metrics:

- ``mtu_error_message_total``

These packets are the basis for path MTU discovery and indicate that packets
along a network path are exceeding max MTU size of the network.

.. include:: ../../beta.rst
