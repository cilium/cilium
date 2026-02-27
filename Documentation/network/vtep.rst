.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _enable_vtep:

***********************************************
VXLAN Tunnel Endpoint (VTEP) Integration (beta)
***********************************************

.. include:: ../beta.rst

The VTEP integration allows third party VTEP devices to send and receive traffic to
and from Cilium-managed pods directly using VXLAN. This allows for example external
load balancers like BIG-IP to load balance traffic to Cilium-managed pods using VXLAN.

VTEP configuration is managed through the ``CiliumVTEPConfig`` CRD, which supports:

- **Dynamic configuration** — add, update, or remove VTEP endpoints without
  restarting Cilium agents
- **Active/Standby failover** — automatic failover to a standby tunnel
  endpoint when the primary becomes unreachable
- **ICMP health monitoring** — continuous health checking of both primary
  and standby connections
- **Anti-flapping protection** — exponential backoff prevents rapid switching
  between connections

.. note::

   This guide assumes that Cilium has been correctly installed in your
   Kubernetes cluster. Please see :ref:`k8s_quick_install` for more
   information. If unsure, run ``cilium status`` and validate that Cilium is up
   and running. This guide also assumes VTEP devices have been configured with
   VTEP endpoint IP, VTEP CIDRs, VTEP MAC addresses (VTEP MAC). The VXLAN network
   identifier (VNI) *must* be configured as VNI ``2``, which represents traffic
   from the VTEP as the world identity. See :ref:`reserved_labels` for more details.


Enable VXLAN Tunnel Endpoint (VTEP) Integration
================================================

Enable VTEP integration via Helm:

.. code-block:: shell-session

    $ helm upgrade cilium cilium/cilium \
        --namespace kube-system \
        --reuse-values \
        --set vtep.enabled=true

    # Restart operator to register the CRD
    $ kubectl rollout restart deploy/cilium-operator -n kube-system

Verify the CRD is registered:

.. code-block:: shell-session

    $ kubectl get crd ciliumvtepconfigs.cilium.io
    NAME                            CREATED AT
    ciliumvtepconfigs.cilium.io     2026-02-17T22:00:00Z


.. _vtep_crd_config:

CiliumVTEPConfig CRD
=====================

The ``CiliumVTEPConfig`` CRD is cluster-scoped with short name ``cvtep``.
Create a resource named ``default`` (or any name) to configure VTEP endpoints.

Basic Example
-------------

.. code-block:: yaml

    apiVersion: cilium.io/v2
    kind: CiliumVTEPConfig
    metadata:
      name: default
    spec:
      cidrMask: "255.255.255.0"
      endpoints:
      - name: dc1-router
        cidr: "10.1.1.0/24"
        tunnelEndpoint: "10.169.72.236"
        mac: "82:36:4c:98:2e:56"

      - name: dc2-router
        cidr: "10.2.1.0/24"
        tunnelEndpoint: "10.169.73.100"
        mac: "aa:bb:cc:dd:ee:01"

Apply the configuration:

.. code-block:: shell-session

    $ kubectl apply -f ciliumvtepconfig.yaml

Verify the status:

.. code-block:: shell-session

    $ kubectl get cvtep
    NAME      ENDPOINTS   ACTIVE         READY   HEALTH   FAILOVER   AGE
    default   2           all-primary    True    True     True       5m

Example with Active/Standby Failover
-------------------------------------

.. code-block:: yaml

    apiVersion: cilium.io/v2
    kind: CiliumVTEPConfig
    metadata:
      name: default
    spec:
      cidrMask: "255.255.255.0"
      endpoints:
      # Simple endpoint — no failover
      - name: dc1-router
        cidr: "10.1.1.0/24"
        tunnelEndpoint: "10.169.72.236"
        mac: "82:36:4c:98:2e:56"

      # Endpoint with active/standby failover
      - name: dc2-router
        cidr: "10.2.1.0/24"
        tunnelEndpoint: "10.169.73.100"
        mac: "aa:bb:cc:dd:ee:01"
        standby:
          tunnelEndpoint: "10.169.73.200"
          mac: "aa:bb:cc:dd:ee:02"

Endpoints **with** ``standby`` get automatic ICMP health monitoring and
failover. Endpoints **without** ``standby`` work as simple static routes
with no health monitoring.

Spec Reference
--------------

.. list-table::
   :header-rows: 1
   :widths: 25 10 65

   * - Field
     - Required
     - Description
   * - ``spec.cidrMask``
     - No
     - Network mask for BPF CIDR lookups. Default: ``255.255.255.0``
   * - ``spec.endpoints``
     - Yes
     - List of VTEP endpoint configurations (1–8 endpoints max)
   * - ``endpoints[].name``
     - Yes
     - Unique name (lowercase alphanumeric with hyphens, 1–63 chars)
   * - ``endpoints[].cidr``
     - Yes
     - Destination CIDR routed to this VTEP (e.g., ``10.1.1.0/24``)
   * - ``endpoints[].tunnelEndpoint``
     - Yes
     - IPv4 address of the primary VTEP device
   * - ``endpoints[].mac``
     - Yes
     - MAC address for encapsulated traffic to primary
   * - ``endpoints[].standby``
     - No
     - Backup connection for automatic failover
   * - ``endpoints[].standby.tunnelEndpoint``
     - Yes*
     - IPv4 address of the standby VTEP device (*required if standby is set*)
   * - ``endpoints[].standby.mac``
     - Yes*
     - MAC address for encapsulated traffic to standby (*required if standby is set*)


.. _vtep_active_standby:

Active/Standby Failover
========================

How It Works
------------

When an endpoint has ``standby`` configured:

1. The health monitor sends ICMP echo probes to **both** primary and standby
   every 5 seconds (configurable).
2. After **3 consecutive failures** (configurable), a connection is marked
   unhealthy.
3. After **3 consecutive successes**, a connection is marked healthy again.
4. **Failover triggers** when the active connection is unhealthy AND the backup
   connection is healthy.
5. The BPF map is updated atomically to point the CIDR to the new active
   tunnel endpoint.
6. CRD status is updated to reflect the new active role.

Failover Decision Matrix
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 15 15 20 50

   * - Primary
     - Standby
     - Active
     - Action
   * - Healthy
     - Healthy
     - Either
     - **No switch** — non-preemptive, stays on current
   * - Down
     - Healthy
     - Primary
     - **Switch to standby**
   * - Healthy
     - Down
     - Standby
     - **Switch to primary**
   * - Down
     - Down
     - Either
     - **No switch** — no flapping, keeps last active

.. note::

   Failover is **non-preemptive**: if the primary recovers after failover to
   standby, traffic stays on standby. It only switches back if the current
   active (standby) fails and primary is healthy.

Anti-Flapping Protection
------------------------

Rapid failovers trigger exponential backoff on the cooldown interval:

- Base cooldown: **30 seconds**
- Each failover doubles the cooldown: 30s → 60s → 120s → 240s → **5 minutes** (max)
- After **10 minutes** of stability (no failovers), the cooldown resets to 30s

This prevents oscillation when both connections are unstable.

Manual Failover Reset
---------------------

To force all endpoints back to primary and clear all cooldown timers:

.. code-block:: shell-session

    $ kubectl annotate cvtep default vtep.cilium.io/reset-failover=true

This is a one-shot operation that:

1. Switches all endpoints back to primary
2. Resets all cooldown timers to base (30s)
3. Resets all failover counters to 0
4. Removes the annotation automatically

Health probing continues after reset. If primary is still down, natural
failover triggers in approximately 45 seconds (15s detection + 30s cooldown).


Checking Status
===============

Quick overview:

.. code-block:: shell-session

    $ kubectl get cvtep
    NAME      ENDPOINTS   ACTIVE           READY   HEALTH   FAILOVER   AGE
    default   2           all-primary      True    True     True       1h

After a failover:

.. code-block:: shell-session

    $ kubectl get cvtep
    NAME      ENDPOINTS   ACTIVE              READY   HEALTH   FAILOVER   AGE
    default   3           1/2 on standby      True    True     False      1h

Detailed per-endpoint status:

.. code-block:: shell-session

    $ kubectl get cvtep default -o yaml

The status section includes:

- ``activeSummary`` — compact view: ``all-primary`` or ``1/2 on standby``
- ``endpointStatuses[]`` — per-endpoint details:

  - ``activeRole`` — ``primary`` or ``standby`` (empty if no standby configured)
  - ``synced`` — whether the BPF map entry is current
  - ``primaryHealth.healthy`` — primary reachability (boolean)
  - ``primaryHealth.latencyMs`` — primary ICMP round-trip time
  - ``primaryHealth.consecutiveFailures`` — current failure streak
  - ``standbyHealth`` — same fields for standby connection
  - ``failoverCount`` — total failover events for this endpoint
  - ``lastFailoverTime`` — timestamp of last failover

BPF map entries (what's actually programmed in the datapath):

.. code-block:: shell-session

    $ kubectl exec -n kube-system ds/cilium -- cilium-dbg bpf vtep list

Monitoring failover events in agent logs:

.. code-block:: shell-session

    $ kubectl logs -n kube-system -l k8s-app=cilium | grep -i failover


Configuration Options
=====================

Health monitoring parameters can be tuned via agent flags or ConfigMap:

.. list-table::
   :header-rows: 1
   :widths: 35 12 53

   * - Flag
     - Default
     - Description
   * - ``--vtep-probe-interval``
     - ``5s``
     - Interval between ICMP health probes for endpoints with standby
   * - ``--vtep-probe-timeout``
     - ``2s``
     - Timeout for each ICMP probe
   * - ``--vtep-failure-threshold``
     - ``3``
     - Consecutive probe failures before marking a connection unhealthy
   * - ``--vtep-min-failover-interval``
     - ``30s``
     - Minimum cooldown between failovers (base for exponential backoff)


How to Test VTEP Integration
=============================

Start up a Linux VM with node network connectivity to Cilium node.
To configure the Linux VM, you will need to be ``root`` user or
run the commands below using ``sudo``.

::

     Test VTEP Integration

     Node IP: 10.169.72.233
    +--------------------------+            VM IP: 10.169.72.236
    |                          |            +------------------+
    | CiliumNode               |            |  Linux VM        |
    |                          |            |                  |
    |  +---------+             |            |                  |
    |  | busybox |             |            |                  |
    |  |         |           ens192<------>ens192              |
    |  +--eth0---+             |            |                  |
    |      |                   |            +-----vxlan2-------+
    |      |                   |
    |   lxcxxx                 |
    |      |                   |
    +------+-----cilium_vxlan--+

.. code-block:: bash

   # Create a vxlan device and set the MAC address.
   ip link add vxlan2 type vxlan id 2 dstport 8472 local 10.169.72.236 dev ens192
   ip link set dev vxlan2 address 82:36:4c:98:2e:56
   ip link set vxlan2 up
   # Configure the VTEP with IP 10.1.1.236 to handle CIDR 10.1.1.0/24.
   ip addr add 10.1.1.236/24 dev vxlan2
   # Assume Cilium podCIDR network is 10.0.0.0/16, add route to 10.0.0.0/16
   ip route add 10.0.0.0/16 dev vxlan2  proto kernel  scope link  src 10.1.1.236
   # Allow Linux VM to send ARP broadcast request to Cilium node for busybox pod
   # ARP resolution through vxlan2 device
   bridge fdb append 00:00:00:00:00:00 dst 10.169.72.233 dev vxlan2

If you are managing multiple VTEPs, follow the above process for each instance.

Testing with CiliumVTEPConfig CRD
----------------------------------

1. Create the CRD configuration pointing to your VTEP VM:

.. code-block:: yaml

    apiVersion: cilium.io/v2
    kind: CiliumVTEPConfig
    metadata:
      name: default
    spec:
      cidrMask: "255.255.255.0"
      endpoints:
      - name: vtep-vm
        cidr: "10.1.1.0/24"
        tunnelEndpoint: "10.169.72.236"
        mac: "82:36:4c:98:2e:56"

2. Apply and verify:

.. code-block:: shell-session

    $ kubectl apply -f ciliumvtepconfig.yaml
    $ kubectl get cvtep
    $ kubectl exec -n kube-system ds/cilium -- cilium-dbg bpf vtep list

3. Test connectivity from the Linux VM:

.. code-block:: shell-session

    $ ping 10.0.1.1    # ping a Cilium-managed pod IP

Testing Active/Standby Failover
--------------------------------

1. Set up two VTEP VMs (primary and standby) with the same CIDR configuration.

2. Create a CRD with standby:

.. code-block:: yaml

    apiVersion: cilium.io/v2
    kind: CiliumVTEPConfig
    metadata:
      name: default
    spec:
      endpoints:
      - name: dc1-router
        cidr: "10.1.1.0/24"
        tunnelEndpoint: "10.169.72.236"
        mac: "82:36:4c:98:2e:56"
        standby:
          tunnelEndpoint: "10.169.72.238"
          mac: "82:36:4c:98:2e:58"

3. Verify health monitoring is active:

.. code-block:: shell-session

    $ kubectl get cvtep
    NAME      ENDPOINTS   ACTIVE         READY   HEALTH   FAILOVER   AGE
    default   1           all-primary    True    True     True       1m

4. Simulate primary failure (e.g., shut down the primary VM or block ICMP):

.. code-block:: shell-session

    # On primary VM
    $ sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

5. Wait ~45 seconds and check failover occurred:

.. code-block:: shell-session

    $ kubectl get cvtep
    NAME      ENDPOINTS   ACTIVE              READY   HEALTH   FAILOVER   AGE
    default   1           1/1 on standby      True    True     False      2m

    $ kubectl get cvtep default -o yaml | grep -A5 activeRole

6. Restore primary and test manual reset:

.. code-block:: shell-session

    # On primary VM
    $ sudo iptables -D INPUT -p icmp --icmp-type echo-request -j DROP

    # Force reset to primary
    $ kubectl annotate cvtep default vtep.cilium.io/reset-failover=true

    $ kubectl get cvtep
    NAME      ENDPOINTS   ACTIVE         READY   HEALTH   FAILOVER   AGE
    default   1           all-primary    True    True     True       3m


Limitations
===========

* Maximum **8 VTEP endpoints** per ``CiliumVTEPConfig`` (BPF map size constraint)
* Each CIDR can only appear in one endpoint
* IPv4 only (tunnel endpoints and CIDRs)
* ICMP health probes require the Cilium agent to have privileged ICMP access
* Only one ``CiliumVTEPConfig`` resource is used (the one named ``default``,
  or the first one found)
* This feature does not work with IPsec encryption between Cilium-managed pods and VTEPs
