.. _admin_guide:

###############
Troubleshooting
###############

This document describes how to troubleshoot Cilium in different deployment
modes. It focuses on a full deployment of Cilium within a datacenter or public
cloud. If you are just looking for a simple way to experiment, we highly
recommend trying out the :ref:`gs_guide` instead.

This guide assumes that you have read the :ref:`arch_guide` which explains all
the components and concepts.

We use GitHub issues to maintain a list of `Cilium Frequently Asked Questions
(FAQ)`_. You can also check there to see if your question(s) is already
addressed.

.. _troubleshooting_k8s:

Kubernetes
==========

Check the status of the DaemonSet_ and verify that all desired instances are in
"ready" state:

.. code:: bash

        $ kubectl --namespace kube-system get ds
        NAME      DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
        cilium    1         1         0         <none>          3s

In this example, we see a desired state of 1 with 0 being ready. This indicates
a problem. The next step is to list all cilium pods by matching on the label
``k8s-app=cilium`` and also sort the list by the restart count of each pod to
easily identify the failing pods:

.. code:: bash

        $ kubectl --namespace kube-system get pods --selector k8s-app=cilium \
                  --sort-by='.status.containerStatuses[0].restartCount'
        NAME           READY     STATUS             RESTARTS   AGE
        cilium-813gf   0/1       CrashLoopBackOff   2          44s

Pod ``cilium-813gf`` is failing and has already been restarted 2 times. Let's
print the logfile of that pod to investigate the cause:

.. code:: bash

        $ kubectl --namespace kube-system logs cilium-813gf
        INFO      _ _ _
        INFO  ___|_| |_|_ _ _____
        INFO |  _| | | | | |     |
        INFO |___|_|_|_|___|_|_|_|
        INFO Cilium 0.8.90 f022e2f Thu, 27 Apr 2017 23:17:56 -0700 go version go1.7.5 linux/amd64
        CRIT kernel version: NOT OK: minimal supported kernel version is >= 4.8

In this example, the cause for the failure is a Linux kernel running on the
worker node which is not meeting :ref:`admin_system_reqs`.

If the cause for the problem is not apparent based on these simple steps,
please come and seek help on our `Slack channel`_.

Monitoring Packet Drops
=======================

When connectivity is not as it should be. A main cause can be unwanted packet
drops on the networking level. There can be various causes for this. The tool
``cilium monitor`` allows you to quickly inspect and see if and where packet
drops happen.

.. code:: bash

    $ cilium monitor --type drop
    Listening for events on 2 CPUs with 64x4096 of shared memory
    Press Ctrl-C to quit
    xx drop (Policy denied (L3)) to endpoint 25729, identity 261->264: fd02::c0a8:210b:0:bf00 -> fd02::c0a8:210b:0:6481 EchoRequest
    xx drop (Policy denied (L3)) to endpoint 25729, identity 261->264: fd02::c0a8:210b:0:bf00 -> fd02::c0a8:210b:0:6481 EchoRequest
    xx drop (Policy denied (L3)) to endpoint 25729, identity 261->264: 10.11.13.37 -> 10.11.101.61 EchoRequest
    xx drop (Policy denied (L3)) to endpoint 25729, identity 261->264: 10.11.13.37 -> 10.11.101.61 EchoRequest
    xx drop (Invalid destination mac) to endpoint 0, identity 0->0: fe80::5c25:ddff:fe8e:78d8 -> ff02::2 RouterSolicitation

The above indicates that a packet to endpoint ID `25729` has been dropped due
to violation of the Layer 3 policy.

Policy Tracing
==============

See section :ref:`policy_tracing` for details and examples on how to use the
policy tracing feature.

Debugging the datapath
======================

The tool ``cilium monitor`` can also be used to retrieve debugging information
from the BPF based datapath. Debugging messages are sent if either the
``cilium-agent`` itself or the respective endpoint is in debug mode. The debug
mode of the agent can be enabled by starting ``cilium-agent`` with the option
``--debug`` enabled or by running ``cilium config debug=true`` for an already
running agent. Debugging of an individual endpoint can be enabled by running
``cilium endpoint config ID Debug=true``


.. code:: bash

    $ cilium endpoint config 3978 Debug=true
    Endpoint 3978 configuration updated successfully
    $ cilium monitor -v --hex
    Listening for events on 2 CPUs with 64x4096 of shared memory
    Press Ctrl-C to quit
    ------------------------------------------------------------------------------
    CPU 00: MARK 0x1c56d86c FROM 3978 DEBUG: 70 bytes Incoming packet from container ifindex 85
    00000000  33 33 00 00 00 02 ae 45  75 73 11 04 86 dd 60 00  |33.....Eus....`.|
    00000010  00 00 00 10 3a ff fe 80  00 00 00 00 00 00 ac 45  |....:..........E|
    00000020  75 ff fe 73 11 04 ff 02  00 00 00 00 00 00 00 00  |u..s............|
    00000030  00 00 00 00 00 02 85 00  15 b4 00 00 00 00 01 01  |................|
    00000040  ae 45 75 73 11 04 00 00  00 00 00 00              |.Eus........|
    CPU 00: MARK 0x1c56d86c FROM 3978 DEBUG: Handling ICMPv6 type=133
    ------------------------------------------------------------------------------
    CPU 00: MARK 0x1c56d86c FROM 3978 Packet dropped 131 (Invalid destination mac) 70 bytes ifindex=0 284->0
    00000000  33 33 00 00 00 02 ae 45  75 73 11 04 86 dd 60 00  |33.....Eus....`.|
    00000010  00 00 00 10 3a ff fe 80  00 00 00 00 00 00 ac 45  |....:..........E|
    00000020  75 ff fe 73 11 04 ff 02  00 00 00 00 00 00 00 00  |u..s............|
    00000030  00 00 00 00 00 02 85 00  15 b4 00 00 00 00 01 01  |................|
    00000040  00 00 00 00                                       |....|
    ------------------------------------------------------------------------------
    CPU 00: MARK 0x7dc2b704 FROM 3978 DEBUG: 86 bytes Incoming packet from container ifindex 85
    00000000  33 33 ff 00 8a d6 ae 45  75 73 11 04 86 dd 60 00  |33.....Eus....`.|
    00000010  00 00 00 20 3a ff fe 80  00 00 00 00 00 00 ac 45  |... :..........E|
    00000020  75 ff fe 73 11 04 ff 02  00 00 00 00 00 00 00 00  |u..s............|
    00000030  00 01 ff 00 8a d6 87 00  20 40 00 00 00 00 fd 02  |........ @......|
    00000040  00 00 00 00 00 00 c0 a8  21 0b 00 00 8a d6 01 01  |........!.......|
    00000050  ae 45 75 73 11 04 00 00  00 00 00 00              |.Eus........|
    CPU 00: MARK 0x7dc2b704 FROM 3978 DEBUG: Handling ICMPv6 type=135
    CPU 00: MARK 0x7dc2b704 FROM 3978 DEBUG: ICMPv6 neighbour soliciation for address b21a8c0:d68a0000

.. _Slack channel: https://cilium.herokuapp.com
.. _DaemonSet: https://kubernetes.io/docs/admin/daemons/
.. _NodeSelector: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
.. _RBAC: https://kubernetes.io/docs/admin/authorization/rbac/
.. _CNI: https://github.com/containernetworking/cni
.. _Volumes: https://kubernetes.io/docs/tasks/configure-pod-container/configure-volume-storage/

.. _iproute2: https://www.kernel.org/pub/linux/utils/net/iproute2/
.. _llvm: http://releases.llvm.org/
.. _Linux kernel: https://www.kernel.org/
.. _Cilium Frequently Asked Questions (FAQ): https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=label%3Akind%2Fquestion%20
