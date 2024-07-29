.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _enable_multicast:

**********************************
Multicast Support in Cilium (Beta)
**********************************

.. include:: ../beta.rst

The multicast capability allows user application to distribute data feeds to
multiple consumers in the Kubernetes cluster.
The container network multicast transmission technology based on eBPF focuses on solving
the problem of efficient multicast transmission in the container network and provides
support for multiple multicast protocols.

This document explains how to enable multicast support and configure Cilium and CiliumNode
with multicast group IP addresses and subscribers.

Prerequisites
=============

This guide assumes that Cilium has been correctly installed in your
Kubernetes cluster. Please see :ref:`k8s_quick_install` for more
information. If unsure, run ``cilium status`` and validate that Cilium is up
and running. This guide also assumes Cilium is configured with vxlan mode,
which is required when using multicast capability.

Multicast only works on kernels >= 5.10 for AMD64, and on kernels >= 6.0 for AArch64.


Enable Multicast Feature
========================

Multicast support can be enabled by updating ``cilium-config`` ConfigMap as following:

.. code-block:: shell-session

   $ cilium config set multicast-enabled true
   ✨ Patching ConfigMap cilium-config with multicast-enabled=true...
   ♻️  Restarted Cilium pods


Configure Multicast and Subscriber IPs
======================================

To use multicast with Cilium, we need to configure multicast group IP addresses and
subscriber list based on the application requirements. This is done by running
``cilium-dbg`` command in each ``cilium-agent`` pod.
Then, multicast subscriber pods can send out IGMP join and multicast
sender pods can start sending multicast stream.

As an example, the following guide uses ``239.255.0.1`` multicast group address.

Get all CiliumNode IP addresses to be set as multicast subscribers:

.. code-block:: shell-session

   $ kubectl get ciliumnodes.cilium.io
   NAME                 CILIUMINTERNALIP   INTERNALIP   AGE
   kind-control-plane   10.244.0.72        172.19.0.2   16m
   kind-worker          10.244.1.86        172.19.0.3   16m

To set multicast IP address, enable multicast BPF maps in each ``cilium-agent``:

.. code-block:: shell-session

   ### add multicast IP address
   $ cilium-dbg bpf multicast group add 239.255.0.1

   ### check multicast IP address
   $ cilium-dbg bpf multicast group list
   Group Address
   239.255.0.1

Then, set the subscriber IP addresses in each ``cilium-agent``:

.. code-block:: shell-session

   ### cilium-agent on kind-control-plane
   $ cilium-dbg bpf multicast subscriber add 239.255.0.1 10.244.1.86
   $ cilium-dbg bpf multicast subscriber list all
   Group           Subscriber      Type
   239.255.0.1     10.244.1.86     Remote Node

   ### cilium-agent on kind-worker
   $ cilium-dbg bpf multicast subscriber add 239.255.0.1 10.244.0.72

.. note::

   This multicast subscriber IP addresses are different CiliumNode IP addresses than your own one.

When you want to remove multicast IP addresses and subscriber list, run the following commands in the ``cilium-agent``.

.. code-block:: shell-session

   $ cilium-dbg bpf multicast group delete 239.255.0.1
   $ cilium-dbg bpf multicast subscriber delete 239.255.0.1 10.244.0.72


Limitations
===========

* The operation needs to be done on each CiliumNode that uses multicast feature.
* This feature does not work with ipsec encryption between Cilium managed pod.
