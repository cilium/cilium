.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gsg_ces:

***************************
CiliumEndpointSlice (beta)
***************************

.. include:: ../../beta.rst

This document describes CiliumEndpointSlice (CES), which enables batching of
CiliumEndpoint (CEP) objects in the cluster to achieve better scalability.
The concept of CiliumEndpointSlice is described in:

.. toctree::
   :maxdepth: 1
   :glob:

   ciliumendpointslice

When enabled, Cilium operator watches CEP objects and group/batch slim versions
of them into CES objects. Cilium agent watches CES objects to learn about
remote endpoints in this mode. API-server stress due to remote endpoint info
propagation should be reduced in this case, allowing for better scalability,
at the cost of potentially longer delay before identity of new endpoint is
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
The CES feature relies on use of CEP. This feature is disabled by default
in current beta status. You can enable the feature by setting the
``enableCiliumEndpointSlice`` value to ``true``.

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --set enableCiliumEndpointSlice=true

Verify that Cilium agent and operator pods are running.

.. code-block:: shell-session

   $ kubectl get pods -n kube-system -l k8s-app=cilium
   NAMESPACE     NAME           READY   STATUS    RESTARTS   AGE
   kube-system   cilium-7tnkq   1/1     Running   0          1d

   $ kubectl get pods -n kube-system -l io.cilium/app=operator
   NAMESPACE     NAME                               READY   STATUS    RESTARTS   AGE
   kube-system   cilium-operator-855979b54b-w8rsm   1/1     Running   0          1d

Validate that the CiliumEndpointSlice CRD has been registered.

.. code-block:: shell-session

   $ kubectl get crds --all-namespaces
   NAME                                         CREATED AT
   [...]
   ciliumendpointslices.cilium.io               2021-11-05T05:41:28Z

Known Issues and Workarounds
============================

Potential Upgrade Impact
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When performing an upgrade from a non-CES mode to CES mode, the operator
will need to process all existing CEPs in the cluster and create CESs for
them. Depending on the load of the cluster, this could take some time.

During this period, new endpoints might experience longer delay before
their identities will propagate to remote nodes. If a newly created pod
is affected by this delay, then it may temporarily fail to establish
connectivity to remote pods in the cluster.

A mitigation strategy is to upgrade the operator from non-CES to CES before
upgrading agents on each node. This will let it start creating CESs right
away, while the agents are still watching CEP resources.

Potential Racing Condition when Identity of An Existing Endpoint Changes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When there's an identity change for any existing resources, e.g., a pod,
a deployment or a statefulset, although unlikely, the endpoints that
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
