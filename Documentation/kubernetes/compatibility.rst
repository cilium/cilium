:orphan:

.. _k8scompatibility:

Kubernetes Compatibility
========================

cilium is compatible with multiple kubernetes API Groups. Some are deprecated
or beta, and may only be available in specific versions of kubernetes.

============= =========================== ==========================
 k8s Version   k8s `NetworkPolicy` API      CiliumNetworkPolicy
============= =========================== ==========================
 <=1.6         * `extensions/v1beta1`_    `ThirdPartyResource`
------------- --------------------------- --------------------------
 1.7           * `extensions/v1beta1`_    `CustomResourceDefinition`,
               * `networking.k8s.io/v1`_  `ThirdPartyResource`
------------- --------------------------- --------------------------
 1.8           * `extensions/v1beta1`_    `CustomResourceDefinition`,
               * `networking.k8s.io/v1`_  `ThirdPartyResource`
------------- --------------------------- --------------------------
 1.9           * `extensions/v1beta1`_    `CustomResourceDefinition`,
               * `networking.k8s.io/v1`_  `ThirdPartyResource`
============= =========================== ==========================

.. _extensions/v1beta1: https://kubernetes.io/docs/api-reference/extensions/v1beta1/definitions/#_v1beta1_networkpolicy
.. _networking.k8s.io/v1: https://kubernetes.io/docs/api-reference/v1.8/#networkpolicy-v1-networking
