.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8scompatibility:

Kubernetes Compatibility
========================

Cilium is compatible with multiple Kubernetes API Groups. Some are deprecated
or beta, and may only be available in specific versions of Kubernetes.

All Kubernetes versions listed are compatible with Cilium:

+------------------------------------------+---------------------------+----------------------------+
| k8s Version                              | k8s NetworkPolicy API     | CiliumNetworkPolicy        |
+------------------------------------------+---------------------------+----------------------------+
|                                          |                           | ``cilium.io/v2`` has a     |
| 1.12, 1.13, 1.14, 1.15, 1.16, 1.17, 1.18 | * `networking.k8s.io/v1`_ | `CustomResourceDefinition` |
+------------------------------------------+---------------------------+----------------------------+

Cilium CRD schema validation
============================

Cilium uses a CRD for its Network Policies in Kubernetes. This CRD might have
changes in its schema validation, which allows it to verify the correctness of
a Cilium Clusterwide Network Policy (CCNP) or a Cilium Network Policy (CNP).

The CRD itself has an annotation, ``io.cilium.k8s.crd.schema.version``, with the
schema definition version. By default, Cilium automatically updates the CRD, and
its validation, with a newer one.

The following table lists all Cilium Versions and their expected schema
validation version:

+-----------------+----------------+
| Cilium          | CNP and CCNP   |
| Version         | Schema Version |
+-----------------+----------------+
| 1.6.0-rc1       | 1.14           |
+-----------------+----------------+
| 1.6.0-rc2       | 1.14           |
+-----------------+----------------+
| 1.6.0-rc3       | 1.14           |
+-----------------+----------------+
| 1.6.0-rc4       | 1.14           |
+-----------------+----------------+
| 1.6.0-rc5       | 1.14           |
+-----------------+----------------+
| 1.6.0-rc6       | 1.14           |
+-----------------+----------------+
| 1.6.0-rc7       | 1.14           |
+-----------------+----------------+
| 1.6.0           | 1.14           |
+-----------------+----------------+
| 1.6.1           | 1.14           |
+-----------------+----------------+
| 1.6.2           | 1.14           |
+-----------------+----------------+
| 1.6.3           | 1.14           |
+-----------------+----------------+
| 1.6.4           | 1.14           |
+-----------------+----------------+
| 1.6.5           | 1.14           |
+-----------------+----------------+
| 1.6.6           | 1.14           |
+-----------------+----------------+
| 1.6.7           | 1.14           |
+-----------------+----------------+
| 1.6.8           | 1.14           |
+-----------------+----------------+
| 1.6.9           | 1.15           |
+-----------------+----------------+
| 1.6.10          | 1.15           |
+-----------------+----------------+
| 1.6             | 1.15.1         |
+-----------------+----------------+
| 1.7.0-rc1       | 1.15           |
+-----------------+----------------+
| 1.7.0-rc2       | 1.16           |
+-----------------+----------------+
| 1.7.0-rc3       | 1.16           |
+-----------------+----------------+
| 1.7.0-rc4       | 1.16           |
+-----------------+----------------+
| 1.7.0           | 1.16           |
+-----------------+----------------+
| 1.7.1           | 1.16           |
+-----------------+----------------+
| 1.7.2           | 1.16           |
+-----------------+----------------+
| 1.7.3           | 1.17           |
+-----------------+----------------+
| 1.7.4           | 1.17           |
+-----------------+----------------+
| 1.7.5           | 1.17           |
+-----------------+----------------+
| 1.7.6           | 1.18           |
+-----------------+----------------+
| 1.7             | 1.18.1         |
+-----------------+----------------+
| 1.8.0-rc1       | 1.19           |
+-----------------+----------------+
| 1.8.0-rc2       | 1.20           |
+-----------------+----------------+
| 1.8.0-rc3       | 1.20           |
+-----------------+----------------+
| 1.8.0-rc4       | 1.20           |
+-----------------+----------------+
| 1.8.0           | 1.21           |
+-----------------+----------------+
| 1.8.1           | 1.21           |
+-----------------+----------------+
| 1.8             | 1.21.1         |
+-----------------+----------------+
| latest / master | 1.22.1         |
+-----------------+----------------+

.. _networking.k8s.io/v1: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#networkpolicy-v1-networking-k8s-io
