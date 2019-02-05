.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _ipvlan:

*********************
Using ipvlan datapath
*********************

This guide explains how to configure Cilium to set up an ipvlan-based
datapath instead of a veth-based one.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue
    if you experience any problems.

Download the Cilium DaemonSet template:

.. code:: bash

    curl -LO https://raw.githubusercontent.com/cilium/cilium/1.4.0/examples/kubernetes/1.13/cilium.yaml

Open the file ``cilium.yaml`` and edit the ``args:`` section. The following
arguments would need to be set for ``cilium-agent`` to run in ipvlan mode:

.. code:: bash

    - --datapath-mode=ipvlan
    - --ipvlan-master-device=eth0
    - --tunnel=disabled
    - --install-iptables-rules=false

The parameter ``--ipvlan-master-device`` must point to a networking device
that is facing the external network and which should be acting as ipvlan
master. ipvlan only supports direct routing mode, therefore tunneling is
disabled. The ``--install-iptables-rules`` parameter is optional and if set
to ``false`` it will trigger ipvlan setup in L3 mode.

Optionally, the agent can also be set up for masquerading all traffic leaving
the ipvlan master device. In that case, ipvlan is operated in L3S mode:

.. code:: bash

    - --datapath-mode=ipvlan
    - --ipvlan-master-device=eth0
    - --tunnel=disabled
    - --masquerade=true

In order for L3S mode to work correctly, a kernel with the following fix
is required: `d5256083f62e <https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git/commit/?id=d5256083f62e2720f75bb3c5a928a0afe47d6bc3>`_ .
This fix is included in stable kernels ``v4.9.155``, ``4.14.98``,
``4.19.20``, ``4.20.6`` or higher.

Apply the DaemonSet file to deploy Cilium and verify it has come up
correctly:

.. code:: bash

    $ kubectl apply -f cilium.yaml
    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

For further information on Cilium's ipvlan datapath mode, see :ref:`arch_guide`.
