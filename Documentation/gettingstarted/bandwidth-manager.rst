.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bandwidth-manager:

************************
Bandwidth Manager (beta)
************************

This guide explains how to configure Cilium's bandwidth manager to
optimize TCP and UDP workloads and efficiently rate limit individual Pods
if needed through the help of EDT (Earliest Departure Time) and eBPF.

The bandwidth manager does not rely on CNI chaining and is natively integrated
into Cilium instead. Hence, it does not make use of the `bandwidth CNI
<https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-traffic-shaping>`_
plugin. Due to scalability concerns in particular for multi-queue network
interfaces, it is not recommended to use the bandwidth CNI plugin which is
based on TBF (Token Bucket Filter) instead of EDT.

Cilium's bandwidth manager supports the ``kubernetes.io/egress-bandwidth`` Pod
annotation which is enforced on egress at the native host networking devices.
The bandwidth enforcement is supported for direct routing as well as tunneling
mode in Cilium.

The ``kubernetes.io/ingress-bandwidth`` annotation is not supported and also not
recommended to use. Limiting bandwidth happens natively at the egress point of
networking devices in order to reduce or pace bandwidth usage on the wire.
Enforcing at ingress would add yet another layer of buffer queueing right in the
critical fast-path of a node via ``ifb`` device where ingress traffic first needs
to be redirected to the ``ifb``'s egress point in order to perform shaping before
traffic can go up the stack. At this point traffic has already occupied the
bandwidth usage on the wire, and the node has already spent resources on
processing the packet. ``kubernetes.io/ingress-bandwidth`` annotation is ignored
by Cilium's bandwidth manager.

.. note::

   Bandwidth Manager requires a v5.1.x or more recent Linux kernel.

.. include:: k8s-install-download-release.rst

Cilium's bandwidth manager is disabled by default on new installations.
To install Cilium with the bandwidth manager enabled, run

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --bandwidthManager=true

To enable the bandwidth manager on an existing installation, run

.. parsed-literal::

   helm upgrade cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --reuse-values \\
     --bandwidthManager=true
   kubectl -n kube-system rollout restart ds/cilium

The native host networking devices are auto detected as native devices which have
the default route on the host or have Kubernetes InternalIP or ExternalIP assigned.
InternalIP is preferred over ExternalIP if both exist. To change and manually specify
the devices, set their names in the ``devices`` helm option, e.g.
``devices='{eth0,eth1,eth2}'``. Each listed device has to be named the same
on all Cilium managed nodes.

Verify that the Cilium Pod has come up correctly:

.. code-block:: shell-session

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

In order to verify whether the bandwidth manager feature has been enabled in Cilium,
the ``cilium status`` CLI command provides visibility through the ``BandwidthManager``
info line. It also dumps a list of devices on which the egress bandwidth limitation
is enforced:

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-xxxxx -- cilium status | grep BandwidthManager
    BandwidthManager:       EDT with BPF   [eth0]

Assuming we have a multi-node cluster, in the next step, we deploy a netperf Pod on
the node named foobar. The following example deployment yaml limits the egress
bandwidth of the netperf Pod on the node's physical device:

.. code-block:: yaml

    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: netperf
    spec:
      selector:
        matchLabels:
          run: netperf
      replicas: 1
      template:
        metadata:
          labels:
            run: netperf
          annotations:
            kubernetes.io/egress-bandwidth: "10M"
        spec:
          nodeName: foobar
          containers:
          - name: netperf
            image: cilium/netperf
            ports:
            - containerPort: 12865

Once up and running, ``netperf`` client can be invoked from a different node in the
cluster using the Pod's IP (in this case ``10.217.0.254``) directly. The test streaming
direction is from the netperf deployment towards the client, hence ``TCP_MAERTS``:

.. code-block:: shell-session

  $ netperf -t TCP_MAERTS -H 10.217.0.254
  MIGRATED TCP MAERTS TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 10.217.0.254 () port 0 AF_INET
  Recv   Send    Send
  Socket Socket  Message  Elapsed
  Size   Size    Size     Time     Throughput
  bytes  bytes   bytes    secs.    10^6bits/sec

   87380  16384  16384    10.00       9.56

As can be seen, egress traffic of the netperf Pod has been limited to 10Mbit per second.

In order to introspect current endpoint bandwidth settings from BPF side, the following
command can be run:

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-xxxxx -- cilium bpf bandwidth list
    IDENTITY   EGRESS BANDWIDTH (BitsPerSec)
    491        10M

Each Pod is represented in Cilium as an :ref:`endpoint` which has an identity. The above
identity can then be correlated with the ``cilium endpoint list`` command.

Limitations
###########

    * Bandwidth enforcement currently does not work in combination with L7 Cilium Network Policies.
      In case they select the Pod at egress, then the bandwidth enforcement will be disabled for
      those Pods.
