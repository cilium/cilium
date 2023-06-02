.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _cilium_operator_internals:

Cilium Operator
===============

This document provides a technical overview of the Cilium Operator and describes
the cluster-wide operations it is responsible for.

Highly Available Cilium Operator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Cilium Operator uses Kubernetes leader election library in conjunction with
lease locks to provide HA functionality. The capability is supported on Kubernetes
versions 1.14 and above. It is Cilium's default behavior since the 1.9 release.

The number of replicas for the HA deployment can be configured using
Helm option ``operator.replicas``.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set operator.replicas=3

.. code-block:: shell-session

    $ kubectl get deployment cilium-operator -n kube-system
    NAME              READY   UP-TO-DATE   AVAILABLE   AGE
    cilium-operator   3/3     3            3           46s

The operator is an integral part of Cilium installations in Kubernetes
environments and is tasked to perform the following operations:

CRD Registration
~~~~~~~~~~~~~~~~

The default behavior of the Cilium Operator is to register the CRDs used by
Cilium. The following custom resources are registered by the Cilium Operator:

-  :ref:`CiliumNetworkPolicy`
-  :ref:`CiliumClusterwideNetworkPolicy`
-  :ref:`CiliumEndpoint <CiliumEndpoint>`
-  CiliumNode
-  CiliumExternalWorkload
-  CiliumIdentity
-  CiliumLocalRedirectPolicy
-  CiliumEgressGatewayPolicy
-  CiliumEndpointSlice
-  CiliumClusterwideEnvoyConfig
-  CiliumEnvoyConfig
-  CiliumBGPPeeringPolicy
-  CiliumLoadBalancerIPPool
-  CiliumNodeConfig
-  CiliumCIDRGroup

IPAM
~~~~

Cilium Operator is responsible for IP address management when running in
the following modes:

-  :ref:`ipam_azure`
-  :ref:`ipam_eni`
-  :ref:`ipam_crd_cluster_pool`

When running in IPAM mode :ref:`k8s_hostscope`, the allocation CIDRs used by
``cilium-agent`` is derived from the fields ``podCIDR`` and ``podCIDRs``
populated by Kubernetes in the Kubernetes ``Node`` resource.

For :ref:`concepts_ipam_crd` IPAM allocation mode, it is the job of Cloud-specific
operator to populate the required information about CIDRs in the
``CiliumNode`` resource.

Cilium currently has native support for the following Cloud providers in CRD IPAM
mode:

- Azure - ``cilium-operator-azure``
- AWS - ``cilium-operator-aws``

For more information on IPAM visit :ref:`address_management`.

Load Balancer IP Address Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When :ref:`lb_ipam` is used, Cilium Operator manages IP address
for ``type: LoadBalancer`` services.

KVStore operations
~~~~~~~~~~~~~~~~~~

These operations are performed only when KVStore is enabled for the
Cilium Operator. In addition, KVStore operations are only required when
``cilium-operator`` is running with any of the below options:

-  ``--synchronize-k8s-services``
-  ``--synchronize-k8s-nodes``
-  ``--identity-allocation-mode=kvstore``

K8s Services synchronization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Cilium Operator performs the job of synchronizing Kubernetes services to
external KVStore configured for the Cilium Operator if running with
``--synchronize-k8s-services`` flag.

The Cilium Operator performs this operation only for shared services (services
that have ``service.cilium.io/shared`` annotation set to true). This is
meaningful when running Cilium to setup a ClusterMesh.

K8s Nodes synchronization
^^^^^^^^^^^^^^^^^^^^^^^^^

Similar to K8s services, Cilium Operator also synchronizes Kubernetes nodes
information to the shared KVStore.

When a ``Node`` object is deleted it is not possible to reliably cleanup
the corresponding ``CiliumNode`` object from the Agent itself. The Cilium Operator
holds the responsibility to garbage collect orphaned ``CiliumNodes``.

CNP/CCNP node status garbage collection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For the same reasons that the Agent cannot reliably delete ``CiliumNode``, 
the Agent also cannot remove the status corresponding to a node in a
CiliumNetworkPolicy (CNP) or CiliumClusterwideNetworkPolicy (CCNP) object.
This operation of node status garbage collection from CNP/CCNP objects is
also performed by the Cilium Operator instead of the Agent.

This behavior can be disabled passing ``--set enableCnpStatusUpdates=false``
to ``helm install`` when installing or updating Cilium:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set enableCnpStatusUpdates=false

Heartbeat update
^^^^^^^^^^^^^^^^

The Cilium Operator periodically updates the Cilium's heartbeat path key
with the current time. The default key for this heartbeat is
``cilium/.heartbeat`` in the KVStore. It is used by Cilium Agents to validate
that KVStore updates can be received.

Policy status update
^^^^^^^^^^^^^^^^^^^^

Cilium Operator performs the operation of CNP/CCNP node status updates
when ``k8s-events-handover`` is enabled. This optimizes Kubernetes events
handling in large clusters. For the node status updates to be handled by
the Cilium Operator, all the K8s events are mirrored to the KVStore, which
is then used to perform operations via the Cilium Operator. This operation
is performed for both ``CiliumNetworkPolicy`` and
``CiliumClusterwideNetworkPolicy`` objects.

For each CNP/CCNP object in the cluster, the Cilium Operator start a status
handler. This handler periodically updates the node statuses for the
CNP/CCNP objects with the status of the policy for the corresponding node.

Identity garbage collection
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each workload in Kubernetes is assigned a security identity that is used
for policy decision making. This identity is based on common workload
markers like labels. Cilium supports two identity allocation mechanisms:

-  CRD Identity allocation
-  KVStore Identity allocation

Both the mechanisms of identity allocation require the Cilium
Operator to perform the garbage collection of stale
identities. This garbage collection is necessary because a 16-bit
unsigned integer represents the security identity, and thus we can only
have a maximum of 65536 identities in the cluster.

CRD Identity garbage collection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

CRD identity allocation uses Kubernetes custom resource
``CiliumIdentity`` to represent a security identity. This is the default
behavior of Cilium and works out of the box in any K8s environment
without any external dependency.

The Cilium Operator maintains a local cache for CiliumIdentities with
the last time they were seen active. A controller runs in the background
periodically which scans this local cache and deletes identities that
have not had their heartbeat life sign updated since
``identity-heartbeat-timeout``.

One thing to note here is that an Identity is always assumed to be live
if it has an endpoint associated with it.

KVStore Identity garbage collection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

While the CRD allocation mode for identities is more common, it is
limited in terms of scale. When running in a very large environment, a
saner choice is to use the KVStore allocation mode. This mode stores
the identities in an external store like etcd.

For more information on Cilium's scalability visit :ref:`scalability_guide`.

The garbage collection mechanism involves scanning the KVStore of all
the identities. For each identity, the Cilium Operator search in the KVStore
if there are any active users of that identity. The entry is deleted from the
KVStore if there are no active users.

CiliumEndpoint garbage collection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CiliumEndpoint object is created by the ``cilium-agent`` for each ``Pod``
in the cluster. The Cilium Operator manages a controller to handle the
garbage collection of orphaned ``CiliumEndpoint`` objects. An orphaned
``CiliumEndpoint`` object means that the owner of the endpoint object is
not active anymore in the cluster. CiliumEndpoints are also considered
orphaned if the owner is an existing Pod in ``PodFailed`` or ``PodSucceeded``
state.
This controller is run periodically if the ``endpoint-gc-interval`` option
is specified and only once during startup if the option is unspecified.

Derivative network policy creation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using Cloud-provider-specific constructs like ``toGroups`` in the
network policy spec, the Cilium Operator performs the job of converting these
constructs to derivative CNP/CCNP objects without these fields.

For more information, see how Cilium network policies incorporate the
use of ``toGroups`` to :ref:`lock down external access using AWS security groups<aws_metadata_with_policy>`.
