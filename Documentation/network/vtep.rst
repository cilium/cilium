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

VTEP configuration is managed through two ``cilium.io/v2alpha1`` CRDs which
together support:

- **Dynamic configuration** — add, update, or remove VTEP endpoints without
  restarting Cilium agents
- **Per-node assignment** — use ``nodeSelector`` to assign different VTEP
  endpoints to different nodes (e.g., per availability zone)
- **Per-endpoint status** — track sync state and errors for each endpoint
  via the per-node ``CiliumVTEPNodeConfig`` object
  (``kubectl get ciliumvtepnodeconfig``)

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

Verify the CRDs are registered:

.. code-block:: shell-session

    $ kubectl get crd ciliumvtepconfigs.cilium.io ciliumvtepnodeconfigs.cilium.io
    NAME                                CREATED AT
    ciliumvtepconfigs.cilium.io         <timestamp>
    ciliumvtepnodeconfigs.cilium.io     <timestamp>


.. _vtep_two_crd_model:

How VTEP Configuration Is Resolved (two-CRD model)
==================================================

VTEP configuration uses two ``cilium.io/v2alpha1`` cluster-scoped CRDs, mirroring
the ``CiliumBGPClusterConfig`` → ``CiliumBGPNodeConfig`` pattern:

- ``CiliumVTEPConfig`` is the **user-authored desired state**. It carries an
  optional ``nodeSelector`` and a list of ``vtepEndpoints``. It has **no**
  ``.status`` — you only ever write this object.
- ``CiliumVTEPNodeConfig`` is **created by the Cilium operator**, one object
  **per node**, with ``metadata.name`` equal to the node name (short name
  ``cvtepnode``). It is read-only for users.

The Cilium operator watches every ``CiliumVTEPConfig``, evaluates each object's
``nodeSelector`` against every node, and writes one ``CiliumVTEPNodeConfig`` per
matching node whose ``spec.vtepEndpoints`` is the resolved set of endpoints that
apply to that node. If the same CIDR is claimed by more than one matching config
for a node, the operator detects the conflict and drops that CIDR from the
node's resolved set.

The Cilium agent on each node watches **only its own** ``CiliumVTEPNodeConfig``
(the one named after its node), programs the BPF LPM map from
``spec.vtepEndpoints``, and is the **sole writer** of that object's ``.status``
(per-endpoint sync state plus a ``Ready`` condition). Readiness therefore lives
on ``CiliumVTEPNodeConfig``, never on ``CiliumVTEPConfig``.

::

    user writes                operator fans out              agent on each node
    +-----------------+        +----------------------+        programs BPF + writes
    | CiliumVTEPConfig|        | CiliumVTEPNodeConfig  |        .status (Ready)
    |  nodeSelector   | -----> |  name == node name    | ----->  +--------------+
    |  vtepEndpoints  |        |  spec.vtepEndpoints   |         | BPF LPM map  |
    |  (no .status)   |        |  (.status subresource)|         +--------------+
    +-----------------+        +----------------------+
       1 per intent              1 per matching node            1 per node


.. _vtep_crd_config:

CiliumVTEPConfig CRD
=====================

The ``CiliumVTEPConfig`` CRD (``apiVersion`` ``cilium.io/v2alpha1``) is cluster-scoped
with short name ``cvtep``. Create a resource named ``default`` (or any name) to
configure VTEP endpoints.

Basic Example
-------------

.. code-block:: yaml

    apiVersion: cilium.io/v2alpha1
    kind: CiliumVTEPConfig
    metadata:
      name: default
    spec:
      vtepEndpoints:
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

The operator resolves this config into one ``CiliumVTEPNodeConfig`` per matching
node. Verify readiness on the per-node objects (status lives there, not on
``CiliumVTEPConfig``):

.. code-block:: shell-session

    $ kubectl get ciliumvtepnodeconfig
    NAME      READY   AGE
    node-01   True    5m
    node-02   True    5m

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
   * - ``spec.vtepEndpoints``
     - Yes
     - List of VTEP endpoint configurations (1–8 endpoints max)
   * - ``vtepEndpoints[].name``
     - Yes
     - Unique name (lowercase alphanumeric with hyphens, 1–63 chars)
   * - ``vtepEndpoints[].cidr``
     - Yes
     - Destination CIDR routed to this VTEP (e.g., ``10.1.1.0/24``)
   * - ``vtepEndpoints[].tunnelEndpoint``
     - Yes
     - IPv4 address of the VTEP device
   * - ``vtepEndpoints[].mac``
     - Yes
     - MAC address for encapsulated traffic


Checking Status
===============

Status lives on the per-node ``CiliumVTEPNodeConfig`` objects (short name
``cvtepnode``), each written by the agent on that node. ``CiliumVTEPConfig``
itself has no ``.status``.

Quick overview — the ``READY`` column reflects each node's agent-reported state:

.. code-block:: shell-session

    $ kubectl get ciliumvtepnodeconfig
    NAME      READY   AGE
    node-01   True    1h
    node-02   True    1h

Check the Ready condition for a specific node:

.. code-block:: shell-session

    $ kubectl get ciliumvtepnodeconfig node-01 \
        -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
    True

Detailed per-endpoint status for a node:

.. code-block:: shell-session

    $ kubectl get ciliumvtepnodeconfig node-01 -o yaml

The status section includes:

- ``endpointCount`` — number of resolved endpoints on this node
- ``conditions`` — overall Ready condition
- ``vtepEndpointStatuses[]`` — per-endpoint details:

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

    apiVersion: cilium.io/v2alpha1
    kind: CiliumVTEPConfig
    metadata:
      name: default
    spec:
      vtepEndpoints:
      - name: vtep-vm
        cidr: "10.1.1.0/24"
        tunnelEndpoint: "10.169.72.236"
        mac: "82:36:4c:98:2e:56"

2. Apply and verify:

.. code-block:: shell-session

    $ kubectl apply -f ciliumvtepconfig.yaml
    $ kubectl get ciliumvtepnodeconfig
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
    apiVersion: cilium.io/v2alpha1
    kind: CiliumVTEPConfig
    metadata:
      name: zone-a
    spec:
      nodeSelector:
        matchLabels:
          topology.kubernetes.io/zone: "zone-a"
      vtepEndpoints:
      - name: dc1-router
        cidr: "10.1.1.0/24"
        tunnelEndpoint: "10.169.72.236"
        mac: "82:36:4c:98:2e:56"
    ---
    # Zone-B nodes use router-b
    apiVersion: cilium.io/v2alpha1
    kind: CiliumVTEPConfig
    metadata:
      name: zone-b
    spec:
      nodeSelector:
        matchLabels:
          topology.kubernetes.io/zone: "zone-b"
      vtepEndpoints:
      - name: dc1-router
        cidr: "10.1.1.0/24"
        tunnelEndpoint: "10.169.73.100"
        mac: "aa:bb:cc:dd:ee:02"

The Cilium operator evaluates each config's ``nodeSelector`` against every node
and writes the resolved endpoints into that node's ``CiliumVTEPNodeConfig``. The
agent on each node then programs the BPF map from its own node config. When node
labels change (e.g., a node is moved to a different zone), the operator
re-resolves the affected node configs and the agents update their BPF map
entries automatically.

If the same CIDR is claimed by multiple configs that match the same node, the
operator treats it as a conflict — that CIDR is dropped from the node's resolved
set (neither config is applied for it) and the conflict is logged by the
operator, naming both offending configs.

A config without ``nodeSelector`` (or with an empty one) applies to **all**
nodes.


Limitations
===========

* Maximum **8 VTEP endpoints** total across all matching configs per node
  (BPF map size constraint)
* Each CIDR can only appear in one matching config per node — on conflict the
  CIDR is dropped from that node's resolved set and logged by the operator
  (not yet surfaced via CRD status or events)
* IPv4 only (tunnel endpoints and CIDRs)
* Each endpoint's prefix length is derived from the ``cidr`` field (e.g., ``/24``,
  ``/25``). Different endpoints may use different prefix lengths; the BPF LPM trie
  performs longest-prefix-match automatically
* This feature does not work with IPsec encryption between Cilium-managed pods and VTEPs
