.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bgp_control_plane_bmp:

BGP Monitoring Protocol (BMP)
=============================

The BGP Control Plane can stream the state of its BGP instances to one or more
external monitoring stations using the `BGP Monitoring Protocol`_ (BMP, RFC
7854). BMP gives an operator a real-time, read-only view of what each Cilium
node sees and advertises over BGP, without logging into individual nodes or
attaching extra BGP peers that could influence route selection.

For each configured station, a Cilium node opens an outbound TCP session and
sends:

* an *Initiation* message identifying the node (the node name is sent as the
  ``sysName``),
* *Peer Up/Down* notifications as BGP sessions are established or torn down,
* *Route Monitoring* messages mirroring the routes in the selected RIB view, and
* optional periodic *Statistics Reports*.

.. _BGP Monitoring Protocol: https://datatracker.ietf.org/doc/html/rfc7854

.. note::

   BMP is a monitoring channel only. It never advertises routes back to Cilium
   and does not affect datapath programming or BGP route selection.

Prerequisites
-------------

* The :ref:`BGP Control Plane <bgp_control_plane>` is enabled
  (``bgpControlPlane.enabled=true``).
* At least one ``CiliumBGPClusterConfig`` is configured, as described in
  :ref:`bgp_control_plane_configuration`.
* The BMP monitoring station is reachable over TCP from the Cilium nodes on the
  configured port. The node initiates the connection, so no inbound ports need
  to be opened on the nodes themselves.

Configuration
-------------

BMP monitoring stations are configured per BGP instance through the
``bmpServers`` field of a ``CiliumBGPClusterConfig``. The stations are
node-agnostic: every node selected by the ``CiliumBGPClusterConfig`` connects
to each listed station.

The example below reuses the peering setup from
:ref:`bgp_control_plane_configuration` and adds a single BMP station that
receives all RIB views together with periodic statistics.

.. code-block:: yaml

    apiVersion: cilium.io/v2
    kind: CiliumBGPClusterConfig
    metadata:
      name: cilium-bgp
    spec:
      nodeSelector:
        matchLabels:
          rack: rack0
      bgpInstances:
      - name: "instance-65000"
        localASN: 65000
        localPort: 179
        peers:
        - name: "peer-65000-tor1"
          peerASN: 65000
          peerAddress: fd00:10:0:0::1
          peerConfigRef:
            name: "cilium-peer"
        bmpServers:
        - name: "bmp-station"
          peerAddress: "10.0.0.5"
          peerPort: 11019
          monitoringPolicy: "all"
          statisticsTimeout: 30

The following fields are available for each entry in ``bmpServers``:

.. list-table::
   :widths: 20 15 65
   :header-rows: 1

   * - Field
     - Default
     - Description
   * - ``name``
     - *(required)*
     - Unique name of the BMP station within the BGP instance.
   * - ``peerAddress``
     - *(required)*
     - IP address of the BMP monitoring station. IPv4 and IPv6 are supported.
   * - ``peerPort``
     - ``11019``
     - TCP port the BMP monitoring station listens on. ``11019`` is the
       IANA-assigned BMP port.
   * - ``monitoringPolicy``
     - ``pre``
     - RIB view streamed to the station. See `Monitoring policies`_.
   * - ``statisticsTimeout``
     - *(disabled)*
     - Interval in seconds between BMP Statistics Reports, in the range
       ``15``-``65535``. When unset, statistics reporting is disabled.

Updating, adding, or removing a station triggers a reconciliation: stations
whose connection parameters changed are torn down and re-established, new
stations are added, and removed stations are disconnected.

Monitoring policies
-------------------

The ``monitoringPolicy`` field selects which Routing Information Base (RIB) view
the node mirrors to the station:

.. list-table::
   :widths: 15 85
   :header-rows: 1

   * - Policy
     - RIB view
   * - ``pre``
     - Pre-policy Adj-RIB-In: routes as received from peers, before inbound
       policy is applied. This is the default.
   * - ``post``
     - Post-policy Adj-RIB-In: routes after inbound policy is applied.
   * - ``both``
     - Both the pre- and post-policy Adj-RIB-In.
   * - ``local``
     - The Local-RIB (RFC 9069): the routes selected by the node for its own
       use.
   * - ``all``
     - All available RIB views.

Example: end-to-end BMP monitoring
----------------------------------

This example deploys an in-cluster BMP collector, points the BGP Control Plane
at it, and observes the routes a node advertises appearing on the collector. It
builds on the peering setup from :ref:`bgp_control_plane_configuration`, so it
assumes you already have a working ``CiliumBGPClusterConfig`` that establishes
at least one BGP session and advertises some routes.

Deploy Loki and Grafana
~~~~~~~~~~~~~~~~~~~~~~~~~

The collector ships its decoded BMP messages to Loki, and Grafana renders them.
If you already run Loki and Grafana, skip this step. Otherwise, deploy a minimal,
self-contained stack for the demo. It creates the ``monitoring`` namespace, a
Loki Service named ``loki`` on port ``3100``, and a Grafana with the Loki data
source pre-provisioned:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/bgp/loki-grafana.yaml

.. warning::

   This stack is single-replica and filesystem-backed for demo and self-service
   verification only. It is not intended for production.

Wait for both to be ready:

.. code-block:: shell-session

    $ kubectl -n monitoring rollout status deploy/loki
    $ kubectl -n monitoring rollout status deploy/grafana

Deploy a BMP collector
~~~~~~~~~~~~~~~~~~~~~~~~

Any RFC 7854 collector works. This example uses `pmbmpd
<https://github.com/pmacct/pmacct>`__, which terminates BMP sessions and writes
each message as JSON, one file per monitored node, alongside a Promtail sidecar
that ships those messages to Loki for the Grafana dashboard later in this guide.
The collector listens on the default BMP port ``11019`` and is exposed inside
the cluster through a ``ClusterIP`` Service so the Cilium nodes can reach it.

.. literalinclude:: ../../../examples/kubernetes/bgp/bmp-collector.yaml
   :language: yaml

The manifest's Promtail sidecar ships to a Grafana Loki install (Service
``loki``, port ``3100``) in the ``monitoring`` namespace by default. If your
Loki lives elsewhere, adjust the client URL in the ``promtail-bmp`` ConfigMap.
Deploy the collector:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/bgp/bmp-collector.yaml

Wait for the collector to be ready and note its ``ClusterIP``:

.. code-block:: shell-session

    $ kubectl -n kube-system rollout status deploy/bmp-collector
    deployment "bmp-collector" successfully rolled out
    $ kubectl -n kube-system get svc bmp-collector -o jsonpath='{.spec.clusterIP}'; echo
    10.96.184.30

Point the BGP Control Plane at the collector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add a ``bmpServers`` entry to your existing ``CiliumBGPClusterConfig``, using the
collector's ``ClusterIP`` as the ``peerAddress``. The snippet below shows only
the BMP addition; keep your existing ``peers`` configuration in place.

.. code-block:: yaml

    apiVersion: cilium.io/v2
    kind: CiliumBGPClusterConfig
    metadata:
      name: cilium-bgp
    spec:
      nodeSelector:
        matchLabels:
          rack: rack0
      bgpInstances:
      - name: "instance-65000"
        localASN: 65000
        # ... existing peers ...
        bmpServers:
        - name: "bmp-collector"
          peerAddress: "10.96.184.30"   # ClusterIP from the previous step
          monitoringPolicy: "all"

Verify the session is established
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The operator propagates ``bmpServers`` to each selected node's
``CiliumBGPNodeConfig``, and the agent opens the session:

.. code-block:: shell-session

    $ kubectl -n kube-system logs ds/cilium -c cilium-agent | grep -i bmp
    level=info msg="Adding BMP station" reconciler=BMP instance=instance-65000 peer=bmp-collector

Observe the routes
~~~~~~~~~~~~~~~~~~~

Read the decoded messages from the collector. You will see an ``init`` message
identifying the node, ``peer_up`` notifications for each BGP session, and
``route_monitor`` messages mirroring the advertised routes. The
``bmp_init_info_sysname`` field carries the node name, and ``sysDescr`` is
``Cilium BGP Control Plane``.

.. code-block:: shell-session

    $ kubectl -n kube-system exec deploy/bmp-collector -- sh -c 'cat /var/log/pmacct/bmp-*.log' | head -2
    {"event_type":"log","bmp_msg_type":"init","bmp_init_info_sysname":"kind-worker","bmp_init_info_sysdescr":"Cilium BGP Control Plane"}
    {"event_type":"log","bmp_msg_type":"route_monitor","bmp_router":"10.0.0.20","peer_ip":"fd00:10:0:0::1","is_post":0,"is_loc":0,"ip_prefix":"10.244.0.0/24","bgp_nexthop":"10.0.0.20","as_path":"65001"}

Advertise or withdraw a route (for example by changing a
``CiliumBGPAdvertisement`` or scaling a workload behind an advertised Service)
and re-read the log to watch the corresponding ``route_monitor`` records appear.

Visualize in Grafana
~~~~~~~~~~~~~~~~~~~~~~

A ready-made dashboard is provided at
``examples/kubernetes/bgp/grafana/bmp-dashboard.json``. It renders message rates
by type, per-node message counts, route-monitor and peer-event counters, a
prefix table, and the raw BMP event stream, all driven by the labels the
Promtail sidecar applies (``job=bmp``, ``bmp_router``, ``bmp_msg_type``).

Import it into Grafana (:menuselection:`Dashboards --> New --> Import`), upload
the JSON file, and select the **Loki** data source when prompted (the
``loki-grafana.yaml`` stack provisions it for you). The dashboard exposes a
**Loki data source** and a **BMP router** dropdown at the top so you can focus on
a single node.

If you deployed the demo stack above, reach Grafana with a port-forward and log
in with ``admin`` / ``admin``:

.. code-block:: shell-session

    $ kubectl -n monitoring port-forward svc/grafana 3000:3000

.. note::

   The dashboard reads from Loki, not Prometheus. BMP is a route-state event
   stream rather than a metrics feed, so it is shipped as logs and queried with
   LogQL. This is independent of the Prometheus-based Cilium metrics described in
   :ref:`install_metrics`.

Clean up
~~~~~~~~

Remove the ``bmpServers`` entry from the ``CiliumBGPClusterConfig`` and delete
the collector (and the demo monitoring stack, if you deployed it):

.. parsed-literal::

    $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes/bgp/bmp-collector.yaml
    $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes/bgp/loki-grafana.yaml

Verifying
---------

The operator copies the ``bmpServers`` from the ``CiliumBGPClusterConfig`` to
the per-node ``CiliumBGPNodeConfig`` of every selected node. Confirm the
propagation with:

.. code-block:: shell-session

    $ kubectl get ciliumbgpnodeconfig <node-name> -o yaml | grep -A6 bmpServers
      bmpServers:
      - monitoringPolicy: all
        name: bmp-station
        peerAddress: 10.0.0.5
        peerPort: 11019
        statisticsTimeout: 30

The agent reconciler logs when it opens or closes a station. The node name in
the log corresponds to the BGP instance:

.. code-block:: shell-session

    $ kubectl -n kube-system logs ds/cilium -c cilium-agent | grep -i bmp
    level=info msg="Adding BMP station" reconciler=BMP instance=instance-65000 peer=bmp-station

Finally, confirm the session from the monitoring station. You should observe an
inbound TCP connection on the configured port followed by a BMP Initiation
message whose ``sysName`` matches the node name and whose ``sysDescr`` is
``Cilium BGP Control Plane``.

Consuming the BMP stream
------------------------

Cilium only produces the BMP stream; a separate monitoring station consumes it.
Any RFC 7854 collector works. A common no-code, Grafana-native pipeline is:

#. `pmbmpd <https://github.com/pmacct/pmacct>`__ terminates the BMP sessions and
   emits each message as JSON.
#. A log shipper (for example Promtail) forwards the JSON to a log store such as
   Loki.
#. Grafana queries the store to visualize peer state, route churn, and
   statistics per node.

Because the node name is carried in the BMP ``sysName``, the collector can
attribute every message to the originating Cilium node.

A decoded Route Monitoring message emitted by ``pmbmpd`` looks like the
following. The same prefix appears once per RIB view: ``is_post: 0`` is the
pre-policy Adj-RIB-In, ``is_post: 1`` is the post-policy Adj-RIB-In, and
``is_loc: 1`` is the Local-RIB.

.. code-block:: json

    {
      "event_type": "route_monitor",
      "bmp_router": "10.0.0.20",
      "peer_ip": "fd00:10:0:0::1",
      "is_post": 0,
      "is_loc": 0,
      "ip_prefix": "10.244.0.0/24",
      "bgp_nexthop": "10.0.0.20",
      "as_path": "65001"
    }

When routes are withdrawn, the collector emits a matching ``route_monitor``
record with the prefix marked as withdrawn, which lets the dashboard track route
churn over time.

Limitations
-----------

* BMP is one-way: the station receives monitoring data only and cannot influence
  Cilium's BGP route selection or datapath.
* The Cilium node always initiates the BMP session (outbound TCP). Passive or
  station-initiated sessions are not supported.
* The address families mirrored to the station are those the BGP instance is
  configured to use; an instance configured for a single address family streams
  only that family.
* On agent restart the BMP sessions are re-established and the current RIB state
  is replayed to the station.
