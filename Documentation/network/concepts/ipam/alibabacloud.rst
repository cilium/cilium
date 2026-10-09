.. _ipam_alibabacloud:

Alibaba Cloud ENI
#################

.. include:: /beta.rst

Alibaba Cloud ENI IPAM allocates private IPv4 addresses from ECS network
interfaces for pods. These addresses are routable in the VPC without a tunnel
or CCM routes for Kubernetes Node PodCIDRs. For installation on ACK BYOCNI,
see the **Alibaba ACK** tab of the
:doc:`Helm installation guide </installation/k8s-install-helm>`.

Architecture
============

The Cilium agent creates a ``CiliumNode`` resource for its node before IPAM
initialization, including its ECS instance and Alibaba Cloud allocation
configuration. The operator discovers instances, ENIs, vSwitches, and security
groups through the ECS and VPC APIs. It publishes ENI information and private
IPv4 addresses in ``status["alibaba-cloud"].enis``.

The agent uses the multi-pool allocator internally. It maps each private IPv4
address on a non-primary ENI to a ``/32`` host prefix in a single ``default``
pool and allocates pod addresses locally from that pool. The primary address
of a secondary ENI is available for pods; all addresses on the primary instance
ENI are reserved for the host. The agent reports its address demand in
``spec.ipam.pools.requested`` and the prefixes it retains in
``spec.ipam.pools.allocated``.

When the available address pool falls below its configured watermark, the
operator assigns additional private addresses on secondary ENIs. When existing
interfaces cannot satisfy demand and the instance has available ENI slots, it
creates and attaches another ENI. The primary instance ENI is excluded from pod
IP allocation. Cloud API calls are performed by the operator rather than for
every pod creation.

The IPAM mode remains ``alibabacloud``. No ``CiliumPodIPPool`` resources are
required, and all pod addresses come from the default pool.

Configuration
=============

Use the networking settings shown in the **Alibaba ACK** tab of the
:doc:`Helm installation guide </installation/k8s-install-helm>`:
``alibabacloud.enabled=true``, ``ipam.mode=alibabacloud``,
``routingMode=native``, and ``enableIPv4Masquerade=false``.
``alibabacloud.enabled`` also enables endpoint routes and automatic
``CiliumNode`` creation. Set the IPAM and routing modes explicitly.

The operator discovers its region through ECS instance metadata and uses the
regional ECS and VPC private API endpoints. Ensure access to metadata, API
endpoints, and DNS. The **Alibaba ACK** tab of the Helm installation guide
documents the RAM permissions and the RRSA or AccessKey credentials used by
the operator.

vSwitch and security group selection
------------------------------------

Use ``alibabacloud.nodeSpec`` Helm values to constrain allocation:

.. code-block:: yaml

   alibabacloud:
     enabled: true
     nodeSpec:
       vSwitches:
         - vsw-example-zone-a
         - vsw-example-zone-b
       securityGroups:
         - sg-example
   ipam:
     mode: alibabacloud
     nodeSpec:
       ipamMinAllocate: 10
       ipamPreAllocate: 8
   routingMode: native
   enableIPv4Masquerade: false

Replace the example resource IDs with resources in your VPC. A vSwitch must
match the node's VPC and availability zone and have sufficient free addresses.
Among matching vSwitches, the operator selects the one with the most available
addresses. Provide eligible vSwitches for every availability zone in the cluster.

Alternatively, use ``alibabacloud.nodeSpec.vSwitchTags`` and
``alibabacloud.nodeSpec.securityGroupTags`` to select tagged resources. Each is
a list of ``key=value`` strings. Explicit vSwitch or security group IDs take
precedence over the corresponding tags. Security groups selected by tags must
belong to the node's VPC. If no security groups are specified, newly created
ENIs inherit the primary ENI's security groups.

See :ref:`helm_reference` for these values and the allocation watermarks in
``ipam.nodeSpec``. ``ipamMinAllocate`` sets the initial minimum pool size;
``ipamPreAllocate`` controls the buffer of available addresses. Account for
this buffer when sizing vSwitches and node pools.

IP release
----------

Releasing excess IP addresses is disabled by default. Enable it with the
operator option ``--alibaba-cloud-release-excess-ips``. The agent relinquishes
unused host prefixes by removing them from ``spec.ipam.pools.allocated`` while
retaining the addresses needed for its allocation buffer. The operator uses
this information and the allocation watermarks to select excess addresses,
groups them by secondary ENI, and releases them through the ECS API.
Primary addresses of ENIs are never released, even when they are not in use
by pods.

Upgrades and rollbacks
======================

The operator continues to publish ``spec.ipam.pool`` and process
``status.ipam.used`` for nodes running older agents that use the CRD allocator.
It also retains the legacy IP release methods for those agents. This allows
old and new agents to coexist during rolling upgrades and rollbacks.

Agents using the multi-pool allocator report demand and retained prefixes in
``spec.ipam.pools`` and clear legacy ``status.ipam.used`` entries. The operator
uses these fields to distinguish the multi-pool protocol from the legacy one.

Verification and troubleshooting
================================

Inspect ``kubectl get ciliumnodes -o yaml`` and the operator logs:

* Check ``spec.ipam.pools.requested`` for the agent's address demand in the
  ``default`` pool.
* Check ``status["alibaba-cloud"].enis`` for the ENIs and private addresses
  discovered by the operator, and confirm that pod ENIs use the expected
  vSwitches.
* Check ``spec.ipam.pools.allocated`` for the ``/32`` prefixes retained by the
  agent. These include addresses kept as an allocation buffer, so the field
  is not a list of only the IPs currently assigned to pods.

For nodes still running a CRD-based agent, inspect ``spec.ipam.pool`` and
``status.ipam.used`` instead. When checking IP release, verify that the operator
option is enabled and that the agent has relinquished the prefixes. Primary
addresses and addresses needed to satisfy allocation watermarks are retained.

If allocation fails, check RAM permissions, instance ENI limits, vSwitch
capacity, and metadata and API connectivity. If pods have addresses but cannot
reach a destination, check security groups, VPC routes, and outbound NAT.
See :ref:`ipam_metrics` and :doc:`/cmdref/cilium-operator-alibabacloud` for
operator metrics and options.
