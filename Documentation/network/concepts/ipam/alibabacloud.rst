.. _ipam_alibabacloud:

Alibaba Cloud ENI
#################

.. include:: /beta.rst

Alibaba Cloud ENI IPAM allocates private IPv4 addresses from ECS network
interfaces for pods. These addresses are routable in the VPC without a tunnel
or CCM routes for Kubernetes Node PodCIDRs. For installation on ACK BYOCNI,
see :ref:`Alibaba Cloud ACK installation <k8s_install_alibabacloud>`.

Architecture
============

The Cilium agent creates a ``CiliumNode`` resource for its node, including its
ECS instance and Alibaba Cloud allocation configuration. The operator discovers
instances, ENIs, vSwitches, and security groups through the ECS and VPC APIs.
It publishes available addresses in ``spec.ipam.pool`` and interface information
in ``status["alibaba-cloud"].enis``. The agent allocates pod addresses locally and
reports allocated addresses in ``status.ipam.used``.

When the available address pool falls below its configured watermark, the
operator assigns additional private addresses on secondary ENIs. When existing
interfaces cannot satisfy demand and the instance has available ENI slots, it
creates and attaches another ENI. The primary instance ENI is excluded from pod
IP allocation. Cloud API calls are performed by the operator rather than for
every pod creation.

Configuration
=============

Use the networking settings shown in the installation guide:
``alibabacloud.enabled=true``, ``ipam.mode=alibabacloud``,
``routingMode=native``, and ``enableIPv4Masquerade=false``.
``alibabacloud.enabled`` also enables endpoint routes and automatic
``CiliumNode`` creation. Set the IPAM and routing modes explicitly.

The operator discovers its region through ECS instance metadata and uses the
regional ECS and VPC private API endpoints. Ensure access to metadata, API
endpoints, and DNS. The installation guide documents the RAM permissions and
the AccessKey Secret used by the operator.

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

Verification and troubleshooting
================================

Inspect ``kubectl get ciliumnodes -o yaml`` and the operator logs. Confirm that
``spec.ipam.pool`` contains addresses from the expected vSwitches and compare
it with ``status.ipam.used``. Interface details are recorded in
``status["alibaba-cloud"].enis``.

If allocation fails, check RAM permissions, instance ENI limits, vSwitch
capacity, and metadata and API connectivity. If pods have addresses but cannot
reach a destination, check security groups, VPC routes, and outbound NAT.
See :ref:`ipam_metrics` and :doc:`/cmdref/cilium-operator-alibabacloud` for
operator metrics and options.
