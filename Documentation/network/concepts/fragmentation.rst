.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _concepts_fragmentation:

IPv4 Fragment Handling
======================

By default, Cilium configures the eBPF datapath to perform IP fragment tracking
to allow protocols that do not support segmentation (such as UDP) to
transparently transmit large messages over the network. This feature may be
configured using the following options:

- ``--enable-ipv4-fragment-tracking``: Enable or disable IPv4 fragment
  tracking. Enabled by default.
- ``--bpf-fragments-map-max``: Control the maximum number of active concurrent
  connections using IP fragmentation. For the defaults, see `bpf_map_limitations`.

.. note::

    When running Cilium with kube-proxy, fragmented NodePort traffic may break due
    to a kernel bug where route MTU is not respected for forwarded packets. Cilium
    fragments tracking requires the first logical fragment to arrive first. Due to the
    kernel bug, additional fragmentation on the outer encapsulation layer may happen
    that causes packet reordering and results in a failure in tracking the fragments.

    The kernel bug has been `fixed <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=02a1b175b0e92d9e0fa5df3957ade8d733ceb6a0>`_
    and backported to all maintained kernel versions. If you observe connectivity problems,
    ensure that the kernel package on your nodes has been upgraded recently before
    reporting an issue.

.. include:: ../../beta.rst
