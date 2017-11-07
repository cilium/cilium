:orphan:

.. _k8scompatibility:

Kubernetes Compatibility
========================

cilium is compatible with multiple kubernetes API Groups. Some are deprecated
or beta, and may only be available in specific versions of kubernetes.

============= =========================== ==========================
 k8s Version   k8s NetworkPolicy_ API      CiliumNetworkPolicy
============= =========================== ==========================
 <=1.6         * `extensions/v1beta1`_    ThirdPartyResource_
------------- --------------------------- --------------------------
 1.7           * `extensions/v1beta1`_    CustomResourceDefinition_
               * `networking.k8s.io/v1`_
------------- --------------------------- --------------------------
 1.8           * `extensions/v1beta1`_    CustomResourceDefinition_
               * `networking.k8s.io/v1`_
------------- --------------------------- --------------------------
 1.9           * `extensions/v1beta1`_    CustomResourceDefinition_
               * `networking.k8s.io/v1`_
============= =========================== ==========================

.. _NetworkPolicy: https://kubernetes.io/docs/concepts/services-networking/network-policies/
.. _extensions/v1beta1: https://kubernetes.io/docs/api-reference/extensions/v1beta1/definitions/#_v1beta1_networkpolicy
.. _networking.k8s.io/v1: https://kubernetes.io/docs/api-reference/v1.8/#networkpolicy-v1-networking
.. _ThirdPartyResource: https://kubernetes.io/docs/tasks/access-kubernetes-api/extend-api-third-party-resource/
.. _CustomResourceDefinition: https://kubernetes.io/docs/concepts/api-extension/custom-resources/#customresourcedefinitions
