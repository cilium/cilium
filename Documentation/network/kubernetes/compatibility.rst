.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8scompatibility:

Kubernetes Compatibility
========================

Cilium is compatible with multiple Kubernetes API Groups. Some are deprecated
or beta, and may only be available in specific versions of Kubernetes.

All Kubernetes versions listed are e2e tested and guaranteed to be compatible
with Cilium. Older Kubernetes versions not listed in this table do not have
Cilium support. Newer Kubernetes versions, while not listed, will depend on the
backward compatibility offered by Kubernetes.

+------------------------------------------------------------------+---------------------------+----------------------------------+
| k8s Version                                                      | k8s NetworkPolicy API     | CiliumNetworkPolicy              |
+------------------------------------------------------------------+---------------------------+----------------------------------+
|                                                                  |                           | ``cilium.io/v2`` has a           |
| 1.16, 1.17, 1.18, 1.19, 1.20, 1.21, 1.22, 1.23, 1.24, 1.25, 1.26 | * `networking.k8s.io/v1`_ | :term:`CustomResourceDefinition` |
+------------------------------------------------------------------+---------------------------+----------------------------------+

Cilium CRD schema validation
============================

Cilium uses a CRD for its Network Policies in Kubernetes. This CRD might have
changes in its schema validation, which allows it to verify the correctness of
a Cilium Clusterwide Network Policy (CCNP) or a Cilium Network Policy (CNP).

The CRD itself has an annotation, ``io.cilium.k8s.crd.schema.version``, with the
schema definition version. By default, Cilium automatically updates the CRD, and
its validation, with a newer one.

The following table lists all Cilium versions and their expected schema
validation version:

.. include:: compatibility-table.rst

.. _networking.k8s.io/v1: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#networkpolicy-v1-networking-k8s-io
