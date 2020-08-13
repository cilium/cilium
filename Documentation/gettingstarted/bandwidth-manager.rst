.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bandwidth-manager:

*****************
Bandwidth Manager
*****************

This guide explains how to configure Cilium's bandwidth manager to in order to
optimize TCP and UDP workloads and efficiently rate limit individual Pods if
needed through the help of BPF.

The bandwidth manager is natively integrated into Cilium and does not make use
of the `bandwidth CNI
<https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-traffic-shaping>`_
plugin. Due to scalability concerns, it is not recommended to use the bandwidth
CNI plugin.

Cilium's bandwidth manager supports the ``kubernetes.io/egress-bandwidth`` Pod
annotation which is enforced on egress at the native host networking devices.

The ``kubernetes.io/ingress-bandwidth`` annotation is not supported and also not
recommended to use.

.. note::

   Bandwidth Manager requires a v5.1.x or more recent Linux kernel.

.. include:: k8s-install-download-release.rst

The Cilium bandwidth manager is enabled by default for new deployments via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system

The option for Helm is controllable through ``global.bandwidthManager`` with a
possible setting of ``true`` (default) and ``false``.

The native host networking devices are auto detected as native devices which have
the default route on the host or have Kubernetes InternalIP or ExternalIP assigned.
InternalIP is preferred over ExternalIP if both exist. To change and manually specify
the devices, set their names in the ``global.devices`` helm option, e.g.
``global.devices='{eth0,eth1,eth2}'``. Each listed device has to be named the same
on all Cilium managed nodes.

Verify that the Cilium Pod has come up correctly:

.. code:: bash

    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

In order to verify whether the bandwidth manager feature has been enabled in Cilium,
the ``cilium status`` CLI command provides visibility through the ``BandwidthManager``
info line. It also dumps a list of devices on which the egress bandwidth limitation
is enforced:

.. parsed-literal::

    kubectl exec -it -n kube-system cilium-xxxxx -- cilium status | grep BandwidthManager
    BandwidthManager:       EDT with BPF   [eth0]

Assuming we have a multi-node cluster, in the next step, we deploy a netperf Pod on
the node named foobar. The following example deployment yaml limits the egress
bandwidth of the netperf Pod on the node's physical device:

.. parsed-literal::

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

.. parsed-literal::

  netperf -t TCP_MAERTS -H 10.217.0.254
  MIGRATED TCP MAERTS TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 10.217.0.254 () port 0 AF_INET
  Recv   Send    Send
  Socket Socket  Message  Elapsed
  Size   Size    Size     Time     Throughput
  bytes  bytes   bytes    secs.    10^6bits/sec

   87380  16384  16384    10.00       9.56

As can be seen, egress traffic of the netperf Pod has been limited to 10Mbit per second.
