.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bandwidth-manager:

*****************
Bandwidth Manager
*****************

This guide explains how to configure Cilium's bandwidth manager to
optimize TCP and UDP workloads and efficiently rate limit individual Pods
if needed through the help of EDT (Earliest Departure Time) and eBPF.
Cilium's bandwidth manager is also prerequisite for enabling BBR congestion
control for Pods as outlined :ref:`below<BBR Pods>`.

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

.. include:: ../../installation/k8s-install-download-release.rst

Cilium's bandwidth manager is disabled by default on new installations.
To install Cilium with the bandwidth manager enabled, run

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set bandwidthManager.enabled=true

To enable the bandwidth manager on an existing installation, run

.. parsed-literal::

   helm upgrade cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --reuse-values \\
     --set bandwidthManager.enabled=true
   kubectl -n kube-system rollout restart ds/cilium

The native host networking devices are auto detected as native devices which have
the default route on the host or have Kubernetes ``InternalIP`` or ``ExternalIP`` assigned.
``InternalIP`` is preferred over ``ExternalIP`` if both exist. To change and manually specify
the devices, set their names in the ``devices`` helm option (e.g.
``devices='{eth0,eth1,eth2}'``). Each listed device has to be named the same
on all Cilium-managed nodes.

Verify that the Cilium Pods have come up correctly:

.. code-block:: shell-session

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m
    cilium-db21a        1/1       Running   0          10m

In order to verify whether the bandwidth manager feature has been enabled in Cilium,
the ``cilium status`` CLI command provides visibility through the ``BandwidthManager``
info line. It also dumps a list of devices on which the egress bandwidth limitation
is enforced:

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium status | grep BandwidthManager
    BandwidthManager:       EDT with BPF [BBR] [eth0]

To verify that egress bandwidth limits are indeed being enforced, one can deploy two
``netperf`` Pods in different nodes — one acting as a server and one acting as the client:

.. code-block:: yaml

    ---
    apiVersion: v1
    kind: Pod
    metadata:
      annotations:
        # Limits egress bandwidth to 10Mbit/s.
        kubernetes.io/egress-bandwidth: "10M"
      labels:
        # This pod will act as server.
        app.kubernetes.io/name: netperf-server
      name: netperf-server
    spec:
      containers:
      - name: netperf
        image: cilium/netperf
        ports:
        - containerPort: 12865
    ---
    apiVersion: v1
    kind: Pod
    metadata:
      # This Pod will act as client.
      name: netperf-client
    spec:
      affinity:
        # Prevents the client from being scheduled to the
        # same node as the server.
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values:
                - netperf-server
            topologyKey: kubernetes.io/hostname
      containers:
      - name: netperf
        args:
        - sleep
        - infinity
        image: cilium/netperf

Once up and running, the ``netperf-client`` Pod can be used to test egress bandwidth enforcement
on the ``netperf-server`` Pod. As the test streaming direction is from the ``netperf-server`` Pod
towards the client, we need to check ``TCP_MAERTS``:

.. code-block:: shell-session

  $ NETPERF_SERVER_IP=$(kubectl get pod netperf-server -o jsonpath='{.status.podIP}')
  $ kubectl exec netperf-client -- \
      netperf -t TCP_MAERTS -H "${NETPERF_SERVER_IP}"
  MIGRATED TCP MAERTS TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 10.217.0.254 () port 0 AF_INET
  Recv   Send    Send
  Socket Socket  Message  Elapsed
  Size   Size    Size     Time     Throughput
  bytes  bytes   bytes    secs.    10^6bits/sec

   87380  16384  16384    10.00       9.56

As can be seen, egress traffic of the ``netperf-server`` Pod has been limited to 10Mbit per second.

In order to introspect current endpoint bandwidth settings from BPF side, the following
command can be run (replace ``cilium-xxxxx`` with the name of the Cilium Pod that is co-located with
the ``netperf-server`` Pod):

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-xxxxxx -- cilium bpf bandwidth list
    IDENTITY   EGRESS BANDWIDTH (BitsPerSec)
    491        10M

Each Pod is represented in Cilium as an :ref:`endpoint` which has an identity. The above
identity can then be correlated with the ``cilium endpoint list`` command.

.. note::

   Bandwidth limits apply on a per-Pod scope. In our example, if multiple
   replicas of the Pod are created, then each of the Pod instances receives
   a 10M bandwidth limit.

.. _BBR Pods:

BBR for Pods
############

The base infrastructure around MQ/FQ setup provided by Cilium's bandwidth manager
also allows for use of TCP `BBR congestion control <https://queue.acm.org/detail.cfm?id=3022184>`_
for Pods.

BBR is in particular suitable when Pods are exposed behind Kubernetes Services which
face external clients from the Internet. BBR achieves higher bandwidths and lower
latencies for Internet traffic, for example, it has been `shown <https://cloud.google.com/blog/products/networking/tcp-bbr-congestion-control-comes-to-gcp-your-internet-just-got-faster>`_ that BBR's throughput can reach as much
as 2,700x higher than today's best loss-based congestion control and queueing delays
can be 25x lower.

.. note::

   BBR for Pods requires a v5.18.x or more recent Linux kernel.

To enable the bandwidth manager with BBR congestion control, deploy with the following:

.. parsed-literal::

   helm upgrade cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --reuse-values \\
     --set bandwidthManager.enabled=true \\
     --set bandwidthManager.bbr=true
   kubectl -n kube-system rollout restart ds/cilium

In order for BBR to work reliably for Pods, it requires a 5.18 or higher kernel.
As outlined in our `Linux Plumbers 2021 talk <https://lpc.events/event/11/contributions/953/>`_,
this is needed since older kernels do not retain timestamps of network packets
when switching from Pod to host network namespace. Due to the latter, the kernel's
pacing infrastructure does not function properly in general (not specific to Cilium).

We helped with fixing this issue for recent kernels to retain timestamps and therefore
to get BBR for Pods working. Prior to that kernel, BBR was only working for sockets
which are in the initial network namespace (hostns). BBR also needs eBPF Host-Routing
in order to retain the network packet's socket association all the way until the
packet hits the FQ queueing discipline on the physical device in the host namespace.
(Without eBPF Host-Routing the packet's socket association would otherwise be orphaned
inside the host stacks forwarding/routing layer.)

In order to verify whether the bandwidth manager with BBR has been enabled in Cilium,
the ``cilium status`` CLI command provides visibility again through the ``BandwidthManager``
info line:

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium status | grep BandwidthManager
    BandwidthManager:       EDT with BPF [BBR] [eth0]

Once this setting is enabled, it will use BBR as a default for all newly spawned Pods.
Ideally, BBR is selected upon initial Cilium installation when the cluster is created
such that all nodes and Pods in the cluster homogeneously use BBR as otherwise there
could be `potential unfairness issues <https://blog.apnic.net/2020/01/10/when-to-use-and-not-use-bbr/>`_
for other connections still using CUBIC. Also note that due to the nature of BBR's
probing you might observe a higher rate of TCP retransmissions compared to CUBIC.

We recommend to use BBR in particular for clusters where Pods are exposed as Services
which serve external clients connecting from the Internet.

Limitations
###########

    * Bandwidth enforcement currently does not work in combination with L7 Cilium Network Policies.
      In case they select the Pod at egress, then the bandwidth enforcement will be disabled for
      those Pods.
    * Bandwidth enforcement doesn't work with nested network namespace environments like Kind. This is because
      they typically don't have access to the global sysctl under ``/proc/sys/net/core`` and the
      bandwidth enforcement depends on them.

.. admonition:: Video
  :class: attention

  For more insights on Cilium's bandwidth manager, check out this `KubeCon talk on Better Bandwidth Management with eBPF <https://www.youtube.com/watch?v=QTSS6ktK8hY>`__.
