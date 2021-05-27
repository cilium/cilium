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

Even when network routing is performed by Cilium using eBPF, by default network
packets still traverse some parts of the regular network stack of the node.
This ensures that all packets still traverse through all of the iptables hooks
in case you depend on them. However, they add significant overhead. For exact
numbers from our test environment, see :ref:`benchmark_throughput` and compare
the results for "Cilium" and "Cilium (legacy host-routing)".

We introduced `eBPF-based host-routing <https://cilium.io/blog/2020/11/10/cilium-19#veth>`_
in Cilium 1.9 to fully bypass iptables and the upper host stack, and to achieve
a faster network namespace switch compared to regular veth device operation.
This option is automatically enabled if your kernel supports it. To validate
whether your installation is running with eBPF host-routing, run ``cilium status``
in any of the Cilium pods and look for the line reporting the status for
"Host Routing" which should state "BPF".

**Requirements:**

* Kernel >= 5.10
* Direct-routing configuration or tunneling
* eBPF-based kube-proxy replacement
* eBPF-based masquerading

Bypass iptables Connection Tracking
===================================

For the case when eBPF Host-Routing cannot be used and thus network packets
still need to traverse the regular network stack in the host namespace,
iptables can add a significant cost. This traversal cost can be minimized
by disabling the connection tracking requirement for all Pod traffic, thus
bypassing the iptables connection tracker.

**Requirements:**

* Kernel >= 4.19.57, >= 5.1.16, >= 5.2
* Direct-routing configuration
* eBPF-based kube-proxy replacement
* eBPF masquerading

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
performance. The overhead of Hubble is somewhere between 1-15% depending
on your network traffic patterns and Hubble aggregation settings.

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
jumbo frames, Cilium will automatically make use of it.

To benefit from this, make sure that your system is configured to use jumbo
frames if your network allows for it.

Bandwidth Manager
=================

Cilium's Bandwidth Manager is responsible for managing network traffic more
efficiently with the goal of improving overall application latency and throughput.

Aside from natively supporting Kubernetes Pod bandwidth annotations, the
`Bandwidth Manager <https://cilium.io/blog/2020/11/10/cilium-19#bwmanager>`_,
first introduced in Cilium 1.9, is also setting up Fair Queue (FQ)
queueing disciplines to support TCP stack pacing (e.g. from EDT/BBR) on all
external-facing network devices as well as setting optimal server-grade sysctl
settings for the networking stack.

**Requirements:**

* Kernel >= 5.1
* Direct-routing configuration or tunneling
* eBPF-based kube-proxy replacement

To enable the Bandwidth Manager:

.. tabs::

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set bandwidthManager=true \\
             --set kubeProxyReplacement=strict

To validate whether your installation is running with Bandwidth Manager,
run ``cilium status`` in any of the Cilium pods and look for the line
reporting the status for "BandwidthManager" which should state "EDT with BPF".

XDP Acceleration
================

Cilium has built-in support for accelerating NodePort, LoadBalancer services
and services with externalIPs for the case where the arriving request needs
to be pushed back out of the node when the backend is located on a remote node.

In that case, the network packets do not need to be pushed all the way to the
upper networking stack, but with the help of XDP, Cilium is able to process
those requests right out of the network driver layer. This helps to reduce
latency and scale-out of services given a single node's forwarding capacity
is dramatically increased. The kube-proxy replacement at the XDP layer is
`available from Cilium 1.8 <https://cilium.io/blog/2020/06/22/cilium-18#kubeproxy-removal>`_.

**Requirements:**

* Kernel >= 4.19.57, >= 5.1.16, >= 5.2
* Native XDP supported driver, check :ref:`our driver list <XDP acceleration>`
* Direct-routing configuration
* eBPF-based kube-proxy replacement

To enable the XDP Acceleration, check out :ref:`our getting started guide <XDP acceleration>` which also contains instructions for setting it
up on public cloud providers.

To validate whether your installation is running with XDP Acceleration,
run ``cilium status`` in any of the Cilium pods and look for the line
reporting the status for "XDP Acceleration" which should say "Native".

eBPF Map Sizing
===============

All eBPF maps are created with upper capacity limits. Insertion beyond the
limit would fail or constrain the scalability of the datapath. Cilium is
using auto-derived defaults based on the given ratio of the total system
memory.

However, the upper capacity limits used by the Cilium agent can be overridden
for advanced users. Please refer to the :ref:`bpf_map_limitations` guide.

Linux Kernel
============

In general, we highly recommend using the most recent LTS stable kernel (such
as >= 5.10) provided by the `kernel community <https://www.kernel.org/category/releases.html>`_
or by a downstream distribution of your choice. The newer the kernel, the more
likely it is that various datapath optimizations can be used.

In our Cilium release blogs, we also regularly highlight some of the eBPF based
kernel work we conduct which implicitly helps Cilium's datapath performance
such as `replacing retpolines with direct jumps in the eBPF JIT <https://cilium.io/blog/2020/02/18/cilium-17#linux-kernel-changes>`_.

Moreover, the kernel allows to configure several options which will help maximize
network performance.

CONFIG_PREEMPT_NONE
-------------------

Run a kernel version with ``CONFIG_PREEMPT_NONE=y`` set. Some Linux
distributions offer kernel images with this option set or you can re-compile
the Linux kernel. ``CONFIG_PREEMPT_NONE=y`` is the recommended setting for
server workloads.

Further Considerations
======================

Various additional settings that we recommend help to tune the system for
specific workloads and to reduce jitter:

tuned network-* profiles
------------------------

The `tuned <https://tuned-project.org/>`_ project offers various profiles to
optimize for deterministic performance at the cost of increased power consumption,
that is, ``network-latency`` and ``network-throughput``, for example. To enable
the former, run:

.. code-block:: shell-session

   tuned-adm profile network-latency

Set CPU governor to performance
-------------------------------

The CPU scaling up and down can impact latency tests and lead to sub-optimal
performance. To achieve maximum consistent performance. Set the CPU governor
to ``performance``:

.. code-block:: bash

   for CPU in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
         echo performance > $CPU
   done

Stop ``irqbalance`` and pin the NIC interrupts to specific CPUs
---------------------------------------------------------------

In case you are running ``irqbalance``, consider disabling it as it might
migrate the NIC's IRQ handling among CPUs and can therefore cause non-deterministic
performance:

.. code-block:: shell-session

   killall irqbalance

We highly recommend to pin the NIC interrupts to specific CPUs in order to
allow for maximum workload isolation!

See `this script <https://github.com/borkmann/netperf_scripts/blob/master/set_irq_affinity>`_
for details and initial pointers on how to achieve this. Note that pinning the
queues can potentially vary in setup between different drivers.

We generally also recommend to check various documentation and performance tuning
guides from NIC vendors on this matter such as from
`Mellanox <https://community.mellanox.com/s/article/performance-tuning-for-mellanox-adapters>`_,
`Intel <https://www.intel.com/content/www/us/en/support/articles/000005811/network-and-i-o/ethernet-products.html>`_
or others for more information.
