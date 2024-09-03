.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _performance_tuning:

************
Tuning Guide
************

This guide helps you optimize a Cilium installation for optimal performance.

Recommendation
==============

The default out of the box deployment of Cilium is focused on maximum compatibility
rather than most optimal performance. If you are a performance-conscious user, here
are the recommended settings for operating Cilium to get the best out of your setup.

.. note::
    In-place upgrade by just enabling the config settings on an existing
    cluster is not possible since these tunings change the underlying datapath
    fundamentals and therefore require Pod or even node restarts.

    The best way to consume this for an existing cluster is to utilize per-node
    configuration for enabling the tunings only on newly spawned nodes which join
    the cluster. See the :ref:`per-node-configuration` page for more details.

Each of the settings for the recommended performance profile are described in more
detail on this page and in this `KubeCon talk <https://sched.co/1R2s5>`__:

- netkit device mode
- eBPF host-routing
- BIG TCP for IPv4/IPv6
- Bandwidth Manager (optional, for BBR congestion control)

**Requirements:**

* Kernel >= 6.8
* Supported NICs for BIG TCP: mlx4, mlx5, ice

To enable the first three settings:

.. tabs::

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set routingMode=native \\
             --set bpf.datapathMode=netkit \\
             --set bpf.masquerade=true \\
             --set ipv6.enabled=true \\
             --set enableIPv6BIGTCP=true \\
             --set ipv4.enabled=true \\
             --set enableIPv4BIGTCP=true \\
             --set kubeProxyReplacement=true

For enabling BBR congestion control in addition, consider adding the following
settings to the above Helm install:

.. tabs::

    .. group-tab:: Helm

       .. parsed-literal::

             --set bandwidthManager.enabled=true \\
             --set bandwidthManager.bbr=true

.. _netkit:

netkit device mode
==================

netkit devices provide connectivity for Pods with the goal to improve throughput
and latency for applications as if they would have resided directly in the host
namespace, meaning, it reduces the datapath overhead for network namespaces down
to zero. The `netkit driver in the kernel <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/netkit.c>`__
has been specifically designed for Cilium's needs and replaces the old-style veth
device type. See also the `KubeCon talk on netkit <https://sched.co/1R2s5>`__ for
more details.

Cilium utilizes netkit in L3 device mode with blackholing traffic from the Pods
when there is no BPF program attached. The Pod specific BPF programs are attached
inside the netkit peer device, and can only be managed from the host namespace
through Cilium. netkit in combination with eBPF-based host-routing achieves a
fast network namespace switch for off-node traffic ingressing into the Pod or
leaving the Pod. When netkit is enabled, Cilium also utilizes tcx for all
attachments to non-netkit devices. This is done for higher efficiency as well
as utilizing BPF links for all Cilium attachments. netkit is available for kernel
6.8 and onwards and it also supports BIG TCP. Once the base kernels become more
ubiquitous, the veth device mode of Cilium will be deprecated.

To validate whether your installation is running with netkit, run ``cilium status``
in any of the Cilium Pods and look for the line reporting the status for
"Device Mode" which should state "netkit". Also, ensure to have eBPF host
routing enabled - the reporting status under "Host Routing" must state "BPF".

.. note::
    In-place upgrade by just enabling netkit on an existing cluster is not
    possible since the CNI plugin cannot simply replace veth with netkit after
    Pod creation. Also, running both flavors in parallel is currently not
    supported.

    The best way to consume this for an existing cluster is to utilize per-node
    configuration for enabling netkit on newly spawned nodes which join the
    cluster. See the :ref:`per-node-configuration` page for more details.

**Requirements:**

* Kernel >= 6.8
* Direct-routing configuration or tunneling
* eBPF host-routing

To enable netkit device mode with eBPF host-routing:

.. tabs::

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set routingMode=native \\
             --set bpf.datapathMode=netkit \\
             --set bpf.masquerade=true \\
             --set kubeProxyReplacement=true

.. _eBPF_Host_Routing:

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

.. _ipv6_big_tcp:

IPv6 BIG TCP
============

IPv6 BIG TCP allows the network stack to prepare larger GSO (transmit) and GRO
(receive) packets to reduce the number of times the stack is traversed which
improves performance and latency. It reduces the CPU load and helps achieve
higher speeds (i.e. 100Gbit/s and beyond).

To pass such packets through the stack BIG TCP adds a temporary Hop-By-Hop header
after the IPv6 one which is stripped before transmitting the packet over the wire.

BIG TCP can operate in a DualStack setup, IPv4 packets will use the old lower
limits (64k) if IPv4 BIG TCP is not enabled, and IPv6 packets will use the new
larger ones (192k). Both IPv4 BIG TCP and IPv6 BIG TCP can be enabled so that
both use the larger one (192k).

Note that Cilium assumes the default kernel values for GSO and GRO maximum sizes
are 64k and adjusts them only when necessary, i.e. if BIG TCP is enabled and the
current GSO/GRO maximum sizes are less than 192k it will try to increase them,
respectively when BIG TCP is disabled and the current maximum values are more
than 64k it will try to decrease them.

BIG TCP doesn't require network interface MTU changes.

.. note::
    In-place upgrade by just enabling BIG TCP on an existing cluster is currently
    not possible since Cilium does not have access into Pods after they have been
    created.

    The best way to consume this for an existing cluster is to either restart Pods
    or to utilize per-node configuration for enabling BIG TCP on newly spawned nodes
    which join the cluster. See the :ref:`per-node-configuration` page for more
    details.

**Requirements:**

* Kernel >= 5.19
* eBPF Host-Routing
* eBPF-based kube-proxy replacement
* eBPF-based masquerading
* Tunneling and encryption disabled
* Supported NICs: mlx4, mlx5, ice

To enable IPv6 BIG TCP:

.. tabs::

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set routingMode=native \\
             --set bpf.masquerade=true \\
             --set ipv6.enabled=true \\
             --set enableIPv6BIGTCP=true \\
             --set kubeProxyReplacement=true

Note that after toggling the IPv6 BIG TCP option the Kubernetes Pods must be
restarted for the changes to take effect.

To validate whether your installation is running with IPv6 BIG TCP,
run ``cilium status`` in any of the Cilium pods and look for the line
reporting the status for "IPv6 BIG TCP" which should state "enabled".

IPv4 BIG TCP
============

Similar to IPv6 BIG TCP, IPv4 BIG TCP allows the network stack to prepare larger
GSO (transmit) and GRO (receive) packets to reduce the number of times the stack
is traversed which improves performance and latency. It reduces the CPU load and
helps achieve higher speeds (i.e. 100Gbit/s and beyond).

To pass such packets through the stack BIG TCP sets IPv4 tot_len to 0 and uses
skb->len as the real IPv4 total length. The proper IPv4 tot_len is set before
transmitting the packet over the wire.

BIG TCP can operate in a DualStack setup, IPv6 packets will use the old lower
limits (64k) if IPv6 BIG TCP is not enabled, and IPv4 packets will use the new
larger ones (192k). Both IPv4 BIG TCP and IPv6 BIG TCP can be enabled so that
both use the larger one (192k).

Note that Cilium assumes the default kernel values for GSO and GRO maximum sizes
are 64k and adjusts them only when necessary, i.e. if BIG TCP is enabled and the
current GSO/GRO maximum sizes are less than 192k it will try to increase them,
respectively when BIG TCP is disabled and the current maximum values are more
than 64k it will try to decrease them.

BIG TCP doesn't require network interface MTU changes.

.. note::
    In-place upgrade by just enabling BIG TCP on an existing cluster is currently
    not possible since Cilium does not have access into Pods after they have been
    created.

    The best way to consume this for an existing cluster is to either restart Pods
    or to utilize per-node configuration for enabling BIG TCP on newly spawned nodes
    which join the cluster. See the :ref:`per-node-configuration` page for more
    details.

**Requirements:**

* Kernel >= 6.3
* eBPF Host-Routing
* eBPF-based kube-proxy replacement
* eBPF-based masquerading
* Tunneling and encryption disabled
* Supported NICs: mlx4, mlx5, ice

To enable IPv4 BIG TCP:

.. tabs::

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set routingMode=native \\
             --set bpf.masquerade=true \\
             --set ipv4.enabled=true \\
             --set enableIPv4BIGTCP=true \\
             --set kubeProxyReplacement=true

Note that after toggling the IPv4 BIG TCP option the Kubernetes Pods
must be restarted for the changes to take effect.

To validate whether your installation is running with IPv4 BIG TCP,
run ``cilium status`` in any of the Cilium pods and look for the line
reporting the status for "IPv4 BIG TCP" which should state "enabled".

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
* eBPF-based masquerading or no masquerading

To enable the iptables connection-tracking bypass:

.. tabs::

    .. group-tab:: Cilium CLI

       .. parsed-literal::

          cilium install |CHART_VERSION| \\
            --set installNoConntrackIptablesRules=true \\
            --set kubeProxyReplacement=true

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set installNoConntrackIptablesRules=true \\
             --set kubeProxyReplacement=true

Hubble
======

Running with Hubble observability enabled can come at the expense of
performance. The overhead of Hubble is somewhere between 1-15% depending
on your network traffic patterns and Hubble aggregation settings.

In clusters with a huge amount of network traffic, cilium-agent might spend
a significant portion of CPU time on processing monitored events and Hubble may
even lose some events.
There are multiple ways to tune Hubble to avoid this.

Increase Hubble Event Queue Size
--------------------------------

The Hubble Event Queue buffers events after they have been emitted from datapath and
before they are processed by the Hubble subsystem. If this queue is full, because Hubble
can't keep up with the amount of emitted events, Cilium will start dropping events.
This does not impact traffic, but the events won't be processed by Hubble and won't show
up in Hubble flows or metrics.

When this happens you will see log lines similar to the following.

::

   level=info msg="hubble events queue is processing messages again: NN messages were lost" subsys=hubble
   level=warning msg="hubble events queue is full: dropping messages; consider increasing the queue size (hubble-event-queue-size) or provisioning more CPU" subsys=hubble

By default the Hubble event queue size is ``#CPU * 1024``, or ``16384`` if your nodes have
more than 16 CPU cores. If you encounter event bursts that result in dropped events,
increasing this queue size might help. We recommend gradually doubling the queue length
until the drops disappear. If you don't see any improvements after increasing the queue
length to 128k, further increasing the event queue size is unlikely to help.

Be aware that increasing the Hubble event queue size will result in increased memory
usage. Depending on your traffic pattern, increasing the queue size by ``10,000`` may
increase the memory usage by up to five Megabytes.

.. tabs::

    .. group-tab:: Cilium CLI

       .. parsed-literal::

           cilium install |CHART_VERSION| \\
             --set hubble.eventQueueSize=32768

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set hubble.eventQueueSize=32768

    .. group-tab:: Per-Node

      If only certain nodes are effected you may also set the queue length on a per-node
      basis using a :ref:`CiliumNodeConfig object <per-node-configuration>`.

      ::

          apiVersion: cilium.io/v2
          kind: CiliumNodeConfig
          metadata:
            namespace: kube-system
            name: set-hubble-event-queue
          spec:
            nodeSelector:
              matchLabels:
                # Update selector to match your nodes
                io.cilium.update-hubble-event-queue: "true"
            defaults:
              hubble-event-queue-size: "32768"

Increasing the Hubble event queue size can't mitigate a consistently high rate of events
being emitted by Cilium datapath and it does not reduce CPU utilization. For this you
should consider increasing the aggregation interval or rate limiting events.

Increase Aggregation Interval
-----------------------------

By default Cilium generates a tracing event on every new connection, any time a packet
contains TCP flags that have not been previously seen for the packet direction, and on
average once per ``monitor-aggregation-interval``, which defaults to 5 seconds.

Depending on your network traffic patterns, the re-emitting of trace events per
aggregation interval can make up a large part of the total events. Increasing the
aggregation interval may decrease CPU utilization and can prevent lost events.

The following will set the aggregation interval to 10 seconds.

.. tabs::
    .. group-tab:: Cilium CLI

       .. parsed-literal::

           cilium install |CHART_VERSION| \\
             --set bpf.events.monitorInterval="10s"

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set bpf.events.monitorInterval="10s"

Rate Limit Events
-----------------

To further prevent high CPU utilization caused by Hubble, you can also set limits on how
many events can be generated by datapath code. Two limits are possible to configure:

* Rate limit - limits how many events on average can be generated
* Burst limit - limits the number of events that can be generated in a span of 1 second

When both limits are set to 0, no BPF events rate limiting is imposed.

.. note::

    Helm configuration for BPF events map rate limiting is experimental and might
    change in upcoming releases.

.. warning::

    When BPF events map rate limiting is enabled, Cilium monitor,
    Hubble observability, Hubble metrics reliability, and Hubble export functionalities
    might be impacted due to dropped events.

To enable eBPF Event Rate Limiting with a rate limit of 10,000 and a burst limit of 50,000:

.. tabs::

    .. group-tab:: Cilium CLI

       .. parsed-literal::

           cilium install |CHART_VERSION| \\
             --set bpf.events.default.rateLimit=10000 \\
             --set bpf.events.default.burstLimit=50000

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set bpf.events.default.rateLimit=10000 \\
             --set bpf.events.default.burstLimit=50000

You can also choose to stop exposing event types in which you
are not interested. For instance if you are mainly interested in
dropped traffic, you can disable "trace" events which will likely reduce
the overall CPU consumption of the agent.

.. tabs::

    .. group-tab:: Cilium CLI

       .. code-block:: shell-session

           cilium config set bpf-events-trace-enabled false

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set bpf.events.trace.enabled=false

.. warning::

    Suppressing one or more event types will impact ``cilium monitor`` as well as Hubble observability capabilities, metrics and exports.

Disable Hubble
--------------

If all this is not sufficient, in order to optimize for maximum performance,
you can disable Hubble:

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
             --set bandwidthManager.enabled=true \\
             --set kubeProxyReplacement=true

To validate whether your installation is running with Bandwidth Manager,
run ``cilium status`` in any of the Cilium pods and look for the line
reporting the status for "BandwidthManager" which should state "EDT with BPF".

BBR congestion control for Pods
===============================

The base infrastructure around MQ/FQ setup provided by Cilium's Bandwidth Manager
also allows for use of TCP `BBR congestion control <https://queue.acm.org/detail.cfm?id=3022184>`_
for Pods. BBR is in particular suitable when Pods are exposed behind Kubernetes
Services which face external clients from the Internet. BBR achieves higher
bandwidths and lower latencies for Internet traffic, for example, it has been
`shown <https://cloud.google.com/blog/products/networking/tcp-bbr-congestion-control-comes-to-gcp-your-internet-just-got-faster>`_
that BBR's throughput can reach as much as 2,700x higher than today's best
loss-based congestion control and queueing delays can be 25x lower.

In order for BBR to work reliably for Pods, it requires a 5.18 or higher kernel.
As outlined in our `Linux Plumbers 2021 talk <https://lpc.events/event/11/contributions/953/>`_,
this is needed since older kernels do not retain timestamps of network packets
when switching from Pod to host network namespace. Due to the latter, the kernel's
pacing infrastructure does not function properly in general (not specific to Cilium).
We helped fixing this issue for recent kernels to retain timestamps and therefore to
get BBR for Pods working.

BBR also needs eBPF Host-Routing in order to retain the network packet's socket
association all the way until the packet hits the FQ queueing discipline on the
physical device in the host namespace.

.. note::
    In-place upgrade by just enabling BBR on an existing cluster is not possible
    since Cilium cannot migrate existing sockets over to BBR congestion control.

    The best way to consume this is to either only enable it on newly built clusters,
    to restart Pods on existing clusters, or to utilize per-node configuration for
    enabling BBR on newly spawned nodes which join the cluster. See the
    :ref:`per-node-configuration` page for more details.

    Note that the use of BBR could lead to a higher amount of TCP retransmissions
    and more aggressive behavior towards TCP CUBIC connections.

**Requirements:**

* Kernel >= 5.18
* Bandwidth Manager
* eBPF Host-Routing

To enable the Bandwidth Manager with BBR for Pods:

.. tabs::

    .. group-tab:: Helm

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set bandwidthManager.enabled=true \\
             --set bandwidthManager.bbr=true \\
             --set kubeProxyReplacement=true

To validate whether your installation is running with BBR for Pods,
run ``cilium status`` in any of the Cilium pods and look for the line
reporting the status for "BandwidthManager" which should then state
``EDT with BPF`` as well as ``[BBR]``.

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
such as `replacing retpolines with direct jumps in the eBPF JIT <https://cilium.io/blog/2020/02/18/cilium-17#upstream-linux>`_.

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
`Mellanox <https://enterprise-support.nvidia.com/s/article/performance-tuning-for-mellanox-adapters>`_,
`Intel <https://www.intel.com/content/www/us/en/support/articles/000005811/network-and-i-o/ethernet-products.html>`_
or others for more information.
