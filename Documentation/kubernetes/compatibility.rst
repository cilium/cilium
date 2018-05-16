:orphan:

.. _k8scompatibility:

Kubernetes Compatibility
========================

Cilium is compatible with multiple Kubernetes API Groups. Some are deprecated
or beta, and may only be available in specific versions of Kubernetes.

All Kubernetes versions listed are compatible with Cilium:

+----------------------+---------------------------+----------------------------+
| k8s Version          | k8s NetworkPolicy API     | CiliumNetworkPolicy        |
+----------------------+---------------------------+----------------------------+
| 1.7                  | * `extensions/v1beta1`_   | ``cilium.io/v2`` has a     |
+----------------------+---------------------------+ `CustomResourceDefinition` |
| 1.8, 1.9, 1.10, 1.11 | * `networking.k8s.io/v1`_ |                            |
+----------------------+---------------------------+----------------------------+

.. _extensions/v1beta1: https://kubernetes.io/docs/api-reference/extensions/v1beta1/definitions/#_v1beta1_networkpolicy
.. _networking.k8s.io/v1: https://kubernetes.io/docs/api-reference/v1.8/#networkpolicy-v1-networking
