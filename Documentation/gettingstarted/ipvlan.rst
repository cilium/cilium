.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

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
    - NAT64
    - IPVLAN with tunneling

.. note::

   The ipvlan-based datapath in L3 mode requires v4.12 or more recent Linux
   kernel, while L3S mode, in addition, requires a stable kernel with the fix
   mentioned in this document (see below).

.. include:: k8s-install-download-release.rst

Generate the required YAML file and deploy it:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.datapathMode=ipvlan \
     --set global.ipvlan.masterDevice=eth0 \
     --set global.tunnel=disabled \
     > cilium.yaml

It is required to specify the master ipvlan device which typically points to a
networking device that is facing the external network. This is done through
setting ``global.ipvlan.masterDevice`` to the name of the networking device
such as ``"eth0"`` or ``"bond0"``, for example. Be aware this option will be
used by all nodes, so it is required this device name is consistent on all
nodes where you are going to deploy Cilium.

The ipvlan datapath only supports direct routing mode right now, therefore
tunneling must be disabled through setting ``tunnel`` to ``"disabled"``.

To make ipvlan work between hosts, routes on each host have to be installed
either manually or automatically by Cilium. The latter can be enabled
through setting ``global.autoDirectNodeRoutes`` to ``"true"``.

The ``global.installIptablesRules`` parameter is optional and if set to
``"false"`` then Cilium will not install any iptables rules which are
mainly for interaction with kube-proxy, and additionally it will trigger
ipvlan setup in L3 mode. For the default case where the latter is ``"true"``,
ipvlan is operated in L3S mode such that netfilter in host namespace
is not bypassed. Optionally, the agent can also be set up for masquerading
all traffic leaving the ipvlan master device if ``global.masquerade`` is set
to ``"true"``. Note that in order for L3S mode to work correctly, a kernel
with the following fix is required: `d5256083f62e <https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git/commit/?id=d5256083f62e2720f75bb3c5a928a0afe47d6bc3>`_ .
This fix is included in stable kernels ``v4.9.155``, ``4.14.98``, ``4.19.20``,
``4.20.6`` or higher. Without this kernel fix, ipvlan in L3S mode cannot
connect to kube-apiserver.

Masquerading with iptables in L3-only mode is not possible since netfilter
hooks are bypassed in the kernel in this mode, hence L3S (symmetric) had
to be introduced in the kernel at the cost of performance. However, Cilium
supports its own BPF-based masquerading which does not rely in any way on
iptables masquerading. If the ``global.installIptablesRules`` parameter is set
to ``"false"`` and ``global.masquerade`` set to ``"true"``, then Cilium will
use the more efficient BPF-based masquerading where ipvlan can remain in
L3 mode as well (instead of L3S). A Linux kernel v4.16 or higher would be
required for BPF-based masquerading.

Example ConfigMap extract for ipvlan in pure L3 mode:

.. code:: bash

   helm template ciliumn \
     --namespace kube-system \
     --set global.datapathMode=ipvlan \
     --set global.ipvlan.masterDevice=bond0 \
     --set global.tunnel=disabled \
     --set global.installIptablesRules=false \
     --set global.autoDirectNodeRoutes=true \
     > cilium.yaml

Example ConfigMap extract for ipvlan in L3S mode with iptables
masquerading all traffic leaving the node:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.datapathMode=ipvlan \
     --set global.ipvlan.masterDevice=bond0 \
     --set global.tunnel=disabled \
     --set global.masquerade=true \
     --set global.autoDirectNodeRoutes=true \
     > cilium.yaml

Example ConfigMap extract for ipvlan in L3 mode with more efficient
BPF-based masquerading instead of iptables-based:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.datapathMode=ipvlan \
     --set global.ipvlan.masterDevice=bond0 \
     --set global.tunnel=disabled \
     --set global.masquerade=true \
     --set global.installIptablesRules=false \
     --set global.autoDirectNodeRoutes=true \
     > cilium.yaml

Apply the DaemonSet file to deploy Cilium and verify that it has
come up correctly:

.. parsed-literal::

    kubectl create -f ./cilium.yaml
    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

For further information on Cilium's ipvlan datapath mode, see :ref:`arch_guide`.
