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

Overall Health
==============

The first step in troubleshooting is to retrieve an overview of the overall
health. This is achieved by running the ``cilium status`` command.

Kubernetes
----------

When using Kubernetes, refer o the ``k8s-cilium-exec.sh`` script to execute
``cilium status`` on all cluster nodes with ease. Download the
``k8s-cilium-exec.sh`` script:

.. code:: bash

    $ curl -sLO releases.cilium.io/v1.0.0-rc11/tools/k8s-cilium-exec.sh
    $ chmod +x ./k8s-cilium-exec.sh

... and run ``cilium status`` on all nodes:

.. code:: bash

    $ ./k8s-cilium-exec.sh cilium status
    KVStore:                Ok   Etcd: http://127.0.0.1:2379 - (Leader) 3.1.10
    ContainerRuntime:       Ok
    Kubernetes:             Ok   OK
    Kubernetes APIs:        ["extensions/v1beta1::Ingress", "core/v1::Node", "CustomResourceDefinition", "cilium/v2::CiliumNetworkPolicy", "networking.k8s.io/v1::NetworkPolicy", "core/v1::Service", "core/v1::Endpoint"]
    Cilium:                 Ok   OK
    NodeMonitor:            Listening for events on 2 CPUs with 64x4096 of shared memory
    Cilium health daemon:   Ok
    Controller Status:      7/7 healthy
    Proxy Status:           OK, ip 10.15.28.238, 0 redirects, port-range 10000-20000
    Cluster health:   1/1 reachable   (2018-02-27T00:24:34Z)

Generic Instructions
--------------------

.. code:: bash

    $ cilium status
    KVStore:                Ok   etcd: 1/1 connected: https://192.168.33.11:2379 - 3.2.7 (Leader)
    ContainerRuntime:       Ok
    Kubernetes:             Ok   OK
    Kubernetes APIs:        ["core/v1::Endpoint", "extensions/v1beta1::Ingress", "core/v1::Node", "CustomResourceDefinition", "cilium/v2::CiliumNetworkPolicy", "networking.k8s.io/v1::NetworkPolicy", "core/v1::Service"]
    Cilium:                 Ok   OK
    NodeMonitor:            Listening for events on 2 CPUs with 64x4096 of shared memory
    Cilium health daemon:   Ok
    IPv4 address pool:      261/65535 allocated
    IPv6 address pool:      4/4294967295 allocated
    Controller Status:      20/20 healthy
    Proxy Status:           OK, ip 10.0.28.238, port-range 10000-20000
    Cluster health:   2/2 reachable   (2018-04-11T15:41:01Z)

Connectivity Issues
===================

Node to node traffic is being dropped
-------------------------------------

Symptom
~~~~~~~

Endpoint to endpoint communication on a single node succeeds but communication
fails between endpoints across multiple nodes.

Troubleshooting steps:
~~~~~~~~~~~~~~~~~~~~~~

1. Run ``cilium-health status`` on the node of the source and destination
   endpoint. It should describe the connectivity from that node to other
   nodes in the cluster, and to a simulated endpoint on each other node.
   Identify points in the cluster that cannot talk to each other. If the
   command does not describe the status of the other node, there may be an
   issue with the KV-Store.

2. Run ``cilium monitor`` on the node of the source and destination endpoint.
   Look for packet drops.

When running in :ref:`arch_overlay` mode:

3. Run ``cilium bpf tunnel list`` and verify that each Cilium node is aware of
   the other nodes in the cluster.  If not, check the logfile for errors.

4. If nodes are being populated correctly, run ``tcpdump -n -i cilium_vxlan`` on
   each node to verify whether cross node traffic is being forwarded correctly
   between nodes.
   
   If packets are being dropped,
   
   * verify that the node IP listed in ``cilium bpf tunnel list`` can reach each
     other.
   * verify that the firewall on each node allows UDP port 4789.

When running in :ref:`arch_direct_routing` mode:

3. Run ``ip route`` or check your cloud provider router and verify that you have
   routes installed to route the endpoint prefix between all nodes.

4. Verify that the firewall on each node permits to route the endpoint IPs.

Cluster Diagnosis Tool
===========================
The ``cluster-diagnosis`` tool can help identify the most commonly encountered
issues in Cilium deployments. The tool currently supports Kubernetes
and Minikube clusters only.

The tool performs various checks and provides hints to fix specific
issues that it has identified.

The following is a list of prerequisites:

* Requires Python >= 2.7.*
* Requires ``kubectl``.
* ``kubectl`` should be pointing to your cluster before running the tool.

You can download the latest version of the cluster-diagnosis.zip file
using the following command:

::

    curl -sLO releases.cilium.io/tools/cluster-diagnosis.zip

Command to run the cluster-diagnosis tool:

::

    python cluster-diagnosis.zip

Command to collect the system dump using the cluster-diagnosis tool:

::

    python cluster-diagnosis.zip sysdump


Cluster connectivity check
==========================

By default when Cilium is run, it launches instances of ``cilium-health`` in
the background to determine overall connectivity status of the cluster. This
tool periodically runs bidirectional traffic across multiple paths through the
cluster and through each node using different protocols to determine the health
status of each path and protocol. At any point in time, cilium-health may be
queried for the connectivity status of the last probe.

.. code:: bash

    $ cilium-health status
    Probe time:   2018-04-11T15:44:01Z
    Nodes:
      k8s1 (localhost):
        Host connectivity to 192.168.34.11:
          ICMP:          OK, RTT=12.50832ms
          HTTP via L3:   OK, RTT=1.341462ms
        Endpoint connectivity to 10.0.242.54:
          ICMP:          OK, RTT=12.760288ms
          HTTP via L3:   OK, RTT=5.419183m
      ...

For each node, the connectivity will be displayed for each protocol and path,
both to the node itself and to an endpoint on that node. The latency specified
is a snapshot at the last time a probe was run, which is typically once per
minute.

Kubernetes
==========

Pod not managed by Cilium
-------------------------

In some situations, Cilium is not managing networking of a pod. These
situations are:

* The pod is running in host networking and will use the host's IP address
  directly. Such pods have full network connectivity but Cilium will not
  provide security policy enforcement for such pods.

* The pod was started before Cilium was deployed. Cilium only manages pods
  that have been deployed after Cilium itself was started. Cilium will not
  provide security policy enforcement for such pods.

You can run the following script to list the pods which are *not* managed by
Cilium:

.. code:: bash

    $ ./contrib/k8s/k8s-unmanaged.sh
    kube-system/cilium-hqpk7
    kube-system/kube-addon-manager-minikube
    kube-system/kube-dns-54cccfbdf8-zmv2c
    kube-system/kubernetes-dashboard-77d8b98585-g52k5
    kube-system/storage-provisioner

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
``cilium endpoint config ID debug=true``


.. code:: bash

    $ cilium endpoint config 3978 debug=true
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
    $ kubectl cp kube-system/cilium-kg8lv:/tmp/cilium-bugtool-20180411-155146.166+0000-UTC-266836983.tar /tmp/cilium-bugtool-20180411-155146.166+0000-UTC-266836983.tar
      [...]

.. Note::

          Please check the archive for sensitive information and strip it
          away before sharing it with us.

Below is an approximate list of the kind of information in the archive.

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

Useful Scripts
==============

Retrieve Cilium pod managing a particular pod
---------------------------------------------

Identifies the Cilium pod that is managing a particular pod in a namespace:

.. code:: bash

    $ curl -sLO releases.cilium.io/v1.1.0/tools/k8s-get-cilium-pod.sh
    $ k8s-get-cilium-pod.sh <podname> <namespace>


Execute a command in all Kubernetes Cilium pods
-----------------------------------------------

Run a command within all Cilium pods of a cluster:

.. code:: bash

    $ curl -sLO releases.cilium.io/v1.1.0/tools/k8s-cilium-exec.sh
    $ ./k8s-cilium-exec.sh <command>

List unmanaged Kubernetes pods
------------------------------

Lists all Kubernetes pods in the cluster for which Cilium does *not* provide
networking. This includes pods running in host-networking mode and pods that
were started before Cilium was deployed.

.. code:: bash

    $ curl -sLO releases.cilium.io/v1.1.0/tools/k8s-unmanaged.sh
    $ ./contrib/k8s/k8s-unmanaged.sh
    kube-system/cilium-hqpk7
    kube-system/kube-addon-manager-minikube
    kube-system/kube-dns-54cccfbdf8-zmv2c
    kube-system/kubernetes-dashboard-77d8b98585-g52k5
    kube-system/storage-provisioner

.. _Slack channel: https://cilium.herokuapp.com
.. _NodeSelector: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
.. _RBAC: https://kubernetes.io/docs/admin/authorization/rbac/
.. _CNI: https://github.com/containernetworking/cni
.. _Volumes: https://kubernetes.io/docs/tasks/configure-pod-container/configure-volume-storage/

.. _Cilium Frequently Asked Questions (FAQ): https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=label%3Akind%2Fquestion%20

.. _issue tracker: https://github.com/cilium/cilium/issues
