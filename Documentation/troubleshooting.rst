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

The above indicates that a packet to endpoint ID ``25729`` has been dropped due
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

Debugging information
=====================

``cilium debuginfo`` can print useful output from the Cilium API. The output
format is in Markdown format so this can be used when reporting a bug on the
`issue tracker`_.  Running without arguments will print to standard output, but
you can also redirect to a file like

::

    cilium debuginfo -f debuginfo.md

.. Note::

          Please check the debuginfo file for sensitive information and strip it
          away before sharing it with us.

Single Node Bugtool
===================

The ``cilium-bugtool`` captures potentially useful information about your
environment for debugging. The tool is meant to be used for debugging a single
Cilium agent node. In the Kubernetes case, if you have multiple Cilium pods,
the tool can retrieve debugging information from all of them. The tool works by
archiving a collection of command output and files from several places. By
default, it writes to the ``tmp`` directory.

::

  cilium-bugtool

When running it with no option as shown above, it will try to copy various
files and execute some commands. If ``kubectl`` is detected, it will search for
Cilium pods. The default label being ``k8s-app=cilium``, but this and the
namespace can be changed via ``k8s-namespace`` and ``k8s-label`` respectively.

If you'd prefer to browse the dump, there is a HTTP flag.

::
  
  cilium-bugtool --serve


If you want to capture the archive from a Kubernetes pod, then the process is a
 bit different

::

    # First we need to get the Cilium pod
    $ kubectl get pods --namespace kube-system
      NAME                          READY     STATUS    RESTARTS   AGE
      cilium-kg8lv                  1/1       Running   0          13m
      kube-addon-manager-minikube   1/1       Running   0          1h
      kube-dns-6fc954457d-sf2nk     3/3       Running   0          1h
      kubernetes-dashboard-6xvc7    1/1       Running   0          1h

    # Run the bugtool from this pod
    $ kubectl -n kube-system exec cilium-kg8lv cilium-bugtool
      [...]

    # Copy the archive from the pod
    $ kubectl cp kube-system/cilium-kg8lv:/tmp/cilium-bugtool-243785589.tar /tmp/cilium-bugtool-243785589.tar
      [...]

.. Note::

          Please check the dump files for sensitive information and strip it
          away before sharing it with us.

Below is an approximate list of the kind of information in the archive. It is
recommended that you verify it before sharing.

* Cilium status
* Cilium version
* Kernel configuration
* Resolve configuration
* Cilium endpoint state
* Cilium logs
* Docker logs
* ``dmesg``
* ``ethtool``
* ``ip a``
* ``ip link``
* ``ip r``
* ``iptables-save``
* ``kubectl -n kube-system get pods``
* ``kubectl get pods,svc for all namespaces``
* ``uname``
* ``uptime``
* ``cilium bpf * list``
* ``cilium endpoint get for each endpoint``
* ``cilium endpoint list``
* ``hostname``
* ``cilium policy get``
* ``cilium service list``
* ...

Cluster-wide Debugging Tool
===========================
The ``clusterdebug`` tool can help identify the most commonly encountered
issues in Cilium deployments. The tool currently supports Kubernetes
and Minikube clusters only.

The tool performs various checks and provides hints to fix specific
issues that it has identified.

The following is a list of prerequisites:

* Requires Python >= 2.7.*
* Requires ``kubectl``.
* ``kubectl`` should be pointing to your cluster before running the tool.

Command to run the cluster-wide debugging tool:

::

    python clusterdebug.zip

Please check the README file for instructions to rebuild the zip file.
You can download the latest version of the clusterdebug.zip file here: //TODO.

.. _Slack channel: https://cilium.herokuapp.com
.. _NodeSelector: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
.. _RBAC: https://kubernetes.io/docs/admin/authorization/rbac/
.. _CNI: https://github.com/containernetworking/cni
.. _Volumes: https://kubernetes.io/docs/tasks/configure-pod-container/configure-volume-storage/

.. _Cilium Frequently Asked Questions (FAQ): https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=label%3Akind%2Fquestion%20

.. _issue tracker: https://github.com/cilium/cilium/issues
