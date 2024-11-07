.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _CiliumEndpointSlice:

***************************
CiliumEndpointSlice
***************************

.. note::
    This is a beta feature. Please provide feedback and file a GitHub issue
    if you experience any problems.

    The tasks needed for graduating this feature "Stable" are documented
    in :gh-issue:`31904`.

This document describes CiliumEndpointSlices (CES), which enable batching of
CiliumEndpoint (CEP) objects in the cluster to achieve better scalability.

When enabled, Cilium Operator watches CEP objects and groups/batches slim versions
of them into CES objects. Cilium Agent watches CES objects to learn about
remote endpoints in this mode. API-server stress due to remote endpoint info
propagation should be reduced in this case, allowing for better scalability,
at the cost of potentially longer delay before identities of new endpoints are
recognized throughout the cluster.

.. note::

   CiliumEndpointSlice is a concept that is specific to Cilium and is not
   related to `Kubernetes' EndpointSlice`_. Although the names are similar, and
   even though the concept of slices in each feature brings similar
   improvements for scalability, they address different problems.

   Kubernetes' Endpoints and EndpointSlices allow Cilium to make load-balancing
   decisions for a particular Service object; Kubernetes' EndpointSlices offer
   a scalable way to track Service back-ends within a cluster.

   By contrast, CiliumEndpoints and CiliumEndpointSlices are used to make
   network routing and policy decisions. So CiliumEndpointSlices focus on
   tracking Pods, batching CEPs to reduce the number of updates to propagate
   through the API-server on large clusters.

   Enabling one does not affect the other.

.. _Kubernetes' EndpointSlice: https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/

Deploy Cilium with CES
=======================

CES are disabled by default. This section describes the steps necessary for enabling them.

Pre-Requisites
~~~~~~~~~~~~~~

* Make sure that CEPs are enabled (the ``--disable-endpoint-crd`` flag is not set to ``true``)
* Make sure you are not relying on the Egress Gateway which is not compatible with CES (see Egress Gateway :ref:`egress-gateway-incompatible-features`)

Migration Procedure
~~~~~~~~~~~~~~~~~~~
In order to minimize endpoint propagation delays, it is recommended to upgrade the Operator first,
let it create all CES objects, and then upgrade the Agents afterwards.

#. Enable CES on the Operator by setting the ``ciliumEndpointSlice.enabled`` value to ``true`` in your Helm chart or
   by directly setting the ``--enable-cilium-endpoint-slice`` flag to ``true`` on the Operator. Re-deploy the Operator.

#. Once the Operator is running, verify that the ``CiliumEndpointSlice`` CRD has been successfully registered:

   .. code-block:: shell-session

      $ kubectl get crd ciliumendpointslices.cilium.io
      NAME                                         CREATED AT
      ciliumendpointslices.cilium.io               2021-11-05T05:41:28Z

#. Verify that the Operator has started creating CES objects:

   .. code-block:: shell-session

      $ kubectl get ces
      NAME                  AGE
      ces-2fvynpvzn-4ncg9   1m17s
      ces-2jyqj8pfl-tdfm8   1m20s

#. Let the Operator create CES objects for all existing CEPs in the cluster. This may take some time, depending on the
   size of the cluster. You can monitor the progress by checking the rate of CES object creation in the cluster, for example by
   looking at the ``apiserver_storage_objects`` Kubernetes metric or by looking at ``ciliumendpointslices`` resource
   creation requests in Kubernetes Audit Logs. You can also monitor the metrics emitted by the Operator, such as ``cilium_operator_ces_sync_total``. All CES-related metrics are documented in the :ref:`ces_metrics` section of the metric documentation.

#. Once the metrics have stabilized (in other words, when the Operator has created CES objects for all existing CEPs), upgrade the
   Cilium Agents on all nodes by setting the ``--enable-cilium-endpoint-slice`` flag to ``true`` and re-deploying them.


Configuration Options
=====================

Several options are available to adjust the performance and behavior of the CES feature:

* You can configure the way CEPs are batched into CES by changing the maximum number of CEPs in a
  CES (``--ces-max-cilium-endpoints-per-ces``) or by changing the way CEPs are grouped into CES (``--ces-slice-mode``).
  Right now two modes are supported: ``identity`` which groups CEPs based on :ref:`security_identities`
  and ``fcfs`` which groups CEPs on a "First Come, First Served" basis.

* You can also fine-tune rate-limiting settings for the Operator communications with the API-server. Refer to the ``--ces-*`` flags for the ``cilium-operator`` binary.

* You can annotate priority namespaces by setting annotation ``cilium.io/ces-namespace`` to the value “priority”. When dealing with large clusters, the propagation of changes during Network Policy updates can be significantly delayed.
  When namespace's annotation ``cilium.io/ces-namespace`` is set to "priority", the updates from this namespace will be processed before non-priority updates. This allows to quicker enforce updated network policy in critical namespaces.

Known Issues and Workarounds
============================

Potential Race Condition when Identity of an Existing Endpoint Changes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When there's an identity change for any existing resource without the pods being re-created
(this can happen when the namespace labels change), in a very unlikely situation, the endpoints that
undergo this change might experience connection disruption.

Root cause for this potential disruption is that when identity of CEPs
change, the operator will try to re-group/re-batch them into a different
set of CESs. This breaks the atomic operation of an UPGRADE into that of
an DELETE and an ADD. If the agent gets the DELETE (from old CES) first,
it will remove the corresponding CEP's information from the ipcache,
resulting in traffic to/from said CEP with an UNKNOWN identity.

In current implementation, Cilium adds a delay (default: 1s) before sending
out the DELETE event. This should greatly reduce the probability of
connection disruption in most cases.
