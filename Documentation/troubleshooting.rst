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

    $ cilium monitor
    Listening for events on 2 CPUs with 64x4096 of shared memory
    Press Ctrl-C to quit

    CPU 00: MARK 0x14126c56 FROM 56326 Packet dropped 159 (Policy denied (L4)) 94 bytes ifindex=18
    00000000  02 fd 7f 53 22 c8 66 56  da 2e fb 84 86 dd 60 0c  |...S".fV......`.|
    00000010  12 14 00 28 06 3f f0 0d  00 00 00 00 00 00 0a 00  |...(.?..........|
    00000020  02 0f 00 00 00 ad f0 0d  00 00 00 00 00 00 0a 00  |................|
    00000030  02 0f 00 00 dc 06 ca 5c  00 50 70 28 32 21 00 00  |.......\.Pp(2!..|
    00000040  00 00 a0 02 6c 98 d5 1b  00 00 02 04 05 6e 04 02  |....l........n..|
    00000050  08 0a 01 5f 07 80 00 00  00 00 01 03 03 07 00 00  |..._............|
    00000060  00 00 00 00                                       |....|

The above indicates that a packet from endpoint ID `56326` has been dropped due
to violation of the Layer 4 policy.

Policy Tracing
==============

See section :ref:`policy_tracing_` for details and examples on how to use the
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

    $ cilium endpoint config 29381 Debug=true
    Endpoint 29381 configuration updated successfully
    $ cilium monitor
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: 118 bytes Incoming packet from container ifindex 20
    00000000  3a f3 07 b3 c6 7f 4e 76  63 5c 53 4e 86 dd 60 02  |:.....Nvc\SN..`.|
    00000010  7a 3c 00 40 3a 40 f0 0d  00 00 00 00 00 00 0a 00  |z<.@:@..........|
    00000020  02 0f 00 00 36 7d f0 0d  00 00 00 00 00 00 0a 00  |....6}..........|
    00000030  02 0f 00 00 ff ff 81 00  c7 05 4a 32 00 05 29 98  |..........J2..).|
    00000040  2c 59 00 00 00 00 1d cd  0c 00 00 00 00 00 10 11  |,Y..............|
    00000050  12 13 14 15 16 17 18 19  1a 1b 1c 1d 1e 1f 20 21  |.............. !|
    00000060  22 23 24 25 26 27 28 29  2a 2b 2c 2d 2e 2f 30 31  |"#$%&'()*+,-./01|
    00000070  32 33 34 35 36 37 00 00                           |234567..|

    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: Handling ICMPv6 type=129
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: CT reverse lookup: sport=0 dport=32768 nexthdr=58 flags=1
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: CT entry found lifetime=24026, proxy_port=0 revnat=0
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: CT verdict: Reply, proxy_port=0 revnat=0
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: Going to host, policy-skip=1
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT reverse lookup: sport=2048 dport=0 nexthdr=1 flags=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT lookup address: 10.15.0.1
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT lookup: sport=0 dport=2048 nexthdr=1 flags=1
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT verdict: New, proxy_port=0 revnat=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT created 1/2: sport=0 dport=2048 nexthdr=1 flags=1 proxy_port=0 revnat=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT created 2/2: 10.15.42.252 revnat=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT created 1/2: sport=0 dport=0 nexthdr=1 flags=3 proxy_port=0 revnat=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: 98 bytes Delivery to ifindex 20
    00000000  4e 76 63 5c 53 4e 3a f3  07 b3 c6 7f 08 00 45 00  |Nvc\SN:.......E.|
    00000010  00 54 d8 41 40 00 3f 01  24 4d 0a 0f 00 01 0a 0f  |.T.A@.?.$M......|
    00000020  2a fc 08 00 67 03 4a 4f  00 01 2a 98 2c 59 00 00  |*...g.JO..*.,Y..|
    00000030  00 00 24 e8 0c 00 00 00  00 00 10 11 12 13 14 15  |..$.............|
    00000040  16 17 18 19 1a 1b 1c 1d  1e 1f 20 21 22 23 24 25  |.......... !"#$%|
    00000050  26 27 28 29 2a 2b 2c 2d  2e 2f 30 31 32 33 34 35  |&'()*+,-./012345|
    00000060  36 37 00 00 00 00 00 00                           |67......|

.. _Slack channel: https://cilium.herokuapp.com
.. _DaemonSet: https://kubernetes.io/docs/admin/daemons/
.. _NodeSelector: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
.. _RBAC: https://kubernetes.io/docs/admin/authorization/rbac/
.. _CNI: https://github.com/containernetworking/cni
.. _Volumes: https://kubernetes.io/docs/tasks/configure-pod-container/configure-volume-storage/

.. _iproute2: https://www.kernel.org/pub/linux/utils/net/iproute2/
.. _llvm: http://releases.llvm.org/
.. _Linux kernel: https://www.kernel.org/
