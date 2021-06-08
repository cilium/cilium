.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _ipvlan:

******************************
IPVLAN based Networking (beta)
******************************

This guide explains how to configure Cilium to set up an ipvlan-based
datapath instead of the default veth-based one.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

    The feature lacks support of the following, which will be resolved in
    upcoming Cilium releases:

    - IPVLAN L2 mode
    - L7 policy enforcement
    - FQDN Policies
    - NAT64
    - IPVLAN with tunneling
    - eBPF-based masquerading

.. note::

   The ipvlan-based datapath in L3 mode requires v4.12 or more recent Linux
   kernel, while L3S mode, in addition, requires a stable kernel with the fix
   mentioned in this document (see below).

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set datapathMode=ipvlan \\
     --set ipvlan.masterDevice=eth0 \\
     --set tunnel=disabled

It is required to specify the master ipvlan device which typically points to a
networking device that is facing the external network. This is done through
setting ``ipvlan.masterDevice`` to the name of the networking device
such as ``"eth0"`` or ``"bond0"``, for example. Be aware this option will be
used by all nodes, so it is required this device name is consistent on all
nodes where you are going to deploy Cilium.

The ipvlan datapath only supports direct routing mode right now, therefore
tunneling must be disabled through setting ``tunnel`` to ``"disabled"``.

To make ipvlan work between hosts, routes on each host have to be installed
either manually or automatically by Cilium. The latter can be enabled
through setting ``autoDirectNodeRoutes`` to ``"true"``.

The ``installIptablesRules`` parameter is optional and if set to
``"false"`` then Cilium will not install any iptables rules which are
mainly for interaction with kube-proxy, and additionally it will trigger
ipvlan setup in L3 mode. For the default case where the latter is ``"true"``,
ipvlan is operated in L3S mode such that netfilter in host namespace
is not bypassed. Optionally, the agent can also be set up for masquerading
all traffic leaving the ipvlan master device if ``masquerade`` is set
to ``"true"``. Note that in order for L3S mode to work correctly, a kernel
with the following fix is required: `d5256083f62e <https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=d5256083f62e2720f75bb3c5a928a0afe47d6bc3>`_ .
This fix is included in stable kernels ``v4.9.155``, ``4.14.98``, ``4.19.20``,
``4.20.6`` or higher. Without this kernel fix, ipvlan in L3S mode cannot
connect to kube-apiserver.

Masquerading with iptables in L3-only mode is not possible since netfilter
hooks are bypassed in the kernel in this mode, hence L3S (symmetric) had
to be introduced in the kernel at the cost of performance.

Example ConfigMap extract for ipvlan in pure L3 mode:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set datapathMode=ipvlan \\
     --set ipvlan.masterDevice=bond0 \\
     --set tunnel=disabled \\
     --set installIptablesRules=false \\
     --set l7Proxy.enabled=false \\
     --set autoDirectNodeRoutes=true

Example ConfigMap extract for ipvlan in L3S mode with iptables
masquerading all traffic leaving the node:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set datapathMode=ipvlan \\
     --set ipvlan.masterDevice=bond0 \\
     --set tunnel=disabled \\
     --set enableIPv4Masquerade=true \\
     --set autoDirectNodeRoutes=true

Verify that it has come up correctly:

.. code-block:: shell-session

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

For further information on Cilium's ipvlan datapath mode, see :ref:`ebpf_datapath`.
