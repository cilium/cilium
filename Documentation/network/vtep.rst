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
- **Per-node assignment** — use ``nodeSelector`` to assign different VTEP
  endpoints to different nodes (e.g., per availability zone)
- **Per-endpoint status** — track sync state and errors for each endpoint
  via ``kubectl get cvtep``

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
    ciliumvtepconfigs.cilium.io     <timestamp>


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
    NAME      ENDPOINTS   READY   AGE
    default   2           True    5m

Spec Reference
--------------

.. list-table::
   :header-rows: 1
   :widths: 25 10 65

   * - Field
     - Required
     - Description
   * - ``spec.nodeSelector``
     - No
     - Label selector to target specific nodes. If omitted, applies to all nodes.
       Uses standard Kubernetes label selector syntax (``matchLabels``, ``matchExpressions``).
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
     - IPv4 address of the VTEP device
   * - ``endpoints[].mac``
     - Yes
     - MAC address for encapsulated traffic


Checking Status
===============

Quick overview:

.. code-block:: shell-session

    $ kubectl get cvtep
    NAME      ENDPOINTS   READY   AGE
    default   2           True    1h

Detailed per-endpoint status:

.. code-block:: shell-session

    $ kubectl get cvtep default -o yaml

The status section includes:

- ``endpointCount`` — number of configured endpoints
- ``conditions`` — overall Ready condition
- ``endpointStatuses[]`` — per-endpoint details:

  - ``synced`` — whether the BPF map entry is current
  - ``lastSyncTime`` — timestamp of last successful sync
  - ``error`` — error message if sync failed

BPF map entries (what's actually programmed in the datapath):

.. code-block:: shell-session

    $ kubectl exec -n kube-system ds/cilium -- cilium-dbg bpf vtep list


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


Per-Node VTEP Assignment
========================

In multi-zone or multi-rack deployments, different nodes may need to reach the
same external CIDR via different VTEP devices. Use ``nodeSelector`` to create
separate ``CiliumVTEPConfig`` objects per node group:

.. code-block:: yaml

    # Zone-A nodes use router-a
    apiVersion: cilium.io/v2
    kind: CiliumVTEPConfig
    metadata:
      name: zone-a
    spec:
      nodeSelector:
        matchLabels:
          topology.kubernetes.io/zone: "zone-a"
      endpoints:
      - name: dc1-router
        cidr: "10.1.1.0/24"
        tunnelEndpoint: "10.169.72.236"
        mac: "82:36:4c:98:2e:56"
    ---
    # Zone-B nodes use router-b
    apiVersion: cilium.io/v2
    kind: CiliumVTEPConfig
    metadata:
      name: zone-b
    spec:
      nodeSelector:
        matchLabels:
          topology.kubernetes.io/zone: "zone-b"
      endpoints:
      - name: dc1-router
        cidr: "10.1.1.0/24"
        tunnelEndpoint: "10.169.73.100"
        mac: "aa:bb:cc:dd:ee:02"

Each Cilium agent evaluates ``nodeSelector`` against its own node's labels and
only applies matching configs. When node labels change (e.g., a node is moved
to a different zone), the agent automatically re-evaluates and updates BPF map
entries.

If the same CIDR appears in multiple configs that match the same node, it is
treated as a conflict — neither CIDR is applied and an error is reported on
both configs' status.

A config without ``nodeSelector`` (or with an empty one) applies to **all**
nodes, maintaining backward compatibility.


Limitations
===========

* Maximum **8 VTEP endpoints** total across all matching configs per node
  (BPF map size constraint)
* Each CIDR can only appear in one matching config per node — conflicts are
  rejected with error status
* IPv4 only (tunnel endpoints and CIDRs)
* Each endpoint's prefix length is derived from the ``cidr`` field (e.g., ``/24``,
  ``/25``). Different endpoints may use different prefix lengths; the BPF LPM trie
  performs longest-prefix-match automatically
* This feature does not work with IPsec encryption between Cilium-managed pods and VTEPs
