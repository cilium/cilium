.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _concepts_fragmentation:

IPv4 fragment handling
======================

By default, Cilium configures the eBPF datapath to perform IP fragment tracking
to allow protocols that do not support segmentation (such as UDP) to
transparently transmit large messages over the network. IP fragment tracking is
implemented in eBPF using an LRU (*Least Recently Used*) map which requires
Linux 4.10 or later. This feature may be configured using the following
options:

- ``--enable-ipv4-fragments-tracking``: Enable or disable IPv4 fragment
  tracking. Enabled by default.
- ``--bpf-fragments-map-max``: Control the maximum number of active concurrent
  connections using IP fragmentation. For the defaults, see `bpf_map_limitations`.

.. include:: ../../beta.rst
