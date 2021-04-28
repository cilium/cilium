.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _performance_tuning:

************
Tuning Guide
************

This guide helps you optimize a Cilium installation for optimal performance.

eBPF Host-Routing
=================

Even when network routing is performed by Cilium using eBPF, network packets
still traverse through some parts of the regular network stack of the node by
default. This default ensures that all packets still traverse through all of
the iptables hooks in case you depend on them. However, they add significant
overhead, for exact numbers, see :ref:`benchmark_throughput` and compare the
results for "Cilium" and "Cilium (legacy host-routing)".

**Requirements:**

* Kernel >= 5.10
* eBPF-based Masquerading

eBPF-based host-routing is automatically enabled if you run a kernel capable of
supporting this. To validate whether your installation is running with eBPF
host-routing, run ``cilium status`` in any of the Cilium pods and look for the
line reporting the status for "Host routing".

Bypass iptables Connection Tracking
===================================

Even when routing is performed by Cilium using eBPF host-routing, network
packets still traverse through the regular network stack in the network
namespace of the container and iptables can again add significant cost. This
traversal cost can be minimized by disabling the connection tracking
requirement for packets forwarded by Cilium and thus bypassing the iptables
connection tracker.

**Requirements:**

* Direct-routing configuration
* kube-proxy replacement enabled (Kernel >= 4.19.57, >= 5.1.16, >= 5.2)

To enable the iptables connection-tracking bypass:

.. tabs::

    .. group-tab:: Cilium CLI

       .. code-block:: shell-session

          cilium install --config install-no-conntrack-iptables-rules=true

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set installNoConntrackIptablesRules=true \\
             --set kubeProxyReplacement=strict

Hubble
======

Running with Hubble observability enabled can come at the expense of
performance. The overhead of Hubble is anywhere between 1-15% depending on your
network traffic pattern and configured Hubble aggregation settings.

In order to optimize for maximum performance, Hubble can be disabled:

.. tabs::

    .. group-tab:: Cilium CLI

       .. code-block:: shell-session

           cilium hubble disable

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set hubble.enabled=false

MTU
===

The maximum transfer unit (MTU) can have a significant impact on the network
throughput of a configuration. Cilium will automatically detect the MTU of the
underlying network devices. Therefore, if your system is configured to use
jumbo frames then Cilium will automatically make us of it. 

To benefit from this, make sure that your system is configured to use jumbo
frames if your network allows for it.

Kernel Optimizations
====================

The kernel allows to configure several options which will help maximize network
performance:

CONFIG_PREEMPT_NONE
-------------------

Run a kernel version with ``CONFIG_PREEMPT_NONE=y`` set. Some Linux
distributions offer kernel images with this option set or you can re-compile
the Linux kernel.

tuned network-latency profile
-----------------------------

Use `tuned <https://tuned-project.org/>`_ with a ``network-latency`` profile:

.. code-block:: shell-session

   tuned-adm profile network-latency

Set CPU governor to performance
-------------------------------

The CPU scaling up and down can impact latency tests and lead to sub-optimal
performance. To achieve maximum consistent performance. Set the CPU governor to
``performance``:

.. code-block:: bash

   for CPU in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
         echo performance > $CPU
   done

Stop ``irqbalance``
-------------------

In case you are running ``irqbalance``, consider disabling it:

.. code-block:: shell-session

   killall irqbalance

Pin the NIC interrupts
----------------------

See `this script
<https://github.com/borkmann/netperf_scripts/blob/master/set_irq_affinity>`_
for details on how to achieve this.
