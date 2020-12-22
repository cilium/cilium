.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_policy:

**************
Network Policy
**************

If you are running Cilium on Kubernetes, you can benefit from Kubernetes
distributing policies for you. In this mode, Kubernetes is responsible for
distributing the policies across all nodes and Cilium will automatically apply
the policies. Three formats are available to configure network policies natively
with Kubernetes:

- The standard `NetworkPolicy` resource which at the time of this writing,
  supports to specify L3/L4 ingress policies with limited egress support marked
  as beta.

- The extended `CiliumNetworkPolicy` format which is available as a
  `CustomResourceDefinition` which supports specification of policies
  at Layers 3-7 for both ingress and egress.

- The `CiliumClusterwideNetworkPolicy` format which is a cluster-scoped
  `CustomResourceDefinition` for specifying cluster-wide policies to be enforced
  by Cilium. The specification is same as that of `CiliumNetworkPolicy` with
  no specified namespace.

Cilium supports running multiple of these policy types at the same time.
However caution should be applied when using multiple policy types at the same
time, as it can be confusing to understand the complete set of allowed traffic
across multiple policy types.  If close attention is not applied this may lead
to unintended policy allow behavior.

.. _NetworkPolicy:
.. _networkpolicy_state:

NetworkPolicy
=============

For more information, see the official `NetworkPolicy documentation
<https://kubernetes.io/docs/concepts/services-networking/network-policies/>`_.

Known missing features for Kubernetes Network Policy:

+-------------------------------+----------------------------------------------+
| Feature                       | Tracking Issue                               |
+===============================+==============================================+
| ``ipBlock`` set with a pod IP | https://github.com/cilium/cilium/issues/9209 |
+-------------------------------+----------------------------------------------+
| SCTP                          | https://github.com/cilium/cilium/issues/5719 |
+-------------------------------+----------------------------------------------+

.. _CiliumNetworkPolicy:

CiliumNetworkPolicy
===================

The `CiliumNetworkPolicy` is very similar to the standard `NetworkPolicy`. The
purpose is provide the functionality which is not yet supported in
`NetworkPolicy`. Ideally all of the functionality will be merged into the
standard resource format and this CRD will no longer be required.

The raw specification of the resource in Go looks like this:

.. code-block:: go

        type CiliumNetworkPolicy struct {
                metav1.TypeMeta `json:",inline"`
                // +optional
                Metadata metav1.ObjectMeta `json:"metadata"`

                // Spec is the desired Cilium specific rule specification.
                Spec *api.Rule `json:"spec,omitempty"`

                // Specs is a list of desired Cilium specific rule specification.
                Specs api.Rules `json:"specs,omitempty"`

                // Status is the status of the Cilium policy rule
                // +optional
                Status CiliumNetworkPolicyStatus `json:"status"`
        }

Metadata
  Describes the policy. This includes:

    * Name of the policy, unique within a namespace
    * Namespace of where the policy has been injected into
    * Set of labels to identify resource in Kubernetes

Spec
  Field which contains a :ref:`policy_rule`
Specs
  Field which contains a list of :ref:`policy_rule`. This field is useful if
  multiple rules must be removed or added automatically.

Status
  Provides visibility into whether the policy has been successfully applied

Examples
========

See :ref:`policy_examples`, :ref:`l4_policy` and :ref:`l7_policy` for
detailed lists of example policies.


.. _CiliumClusterwideNetworkPolicy:

CiliumClusterwideNetworkPolicy
==============================

`CiliumClusterwideNetworkPolicy` is similar to `CiliumNetworkPolicy`, except
(1) policies defined by `CiliumClusterwideNetworkPolicy` are non-namespaced and
cluster-scoped, and (2) it enables the use of :ref:`NodeSelector`. Internally
the policy is composed of `CiliumNetworkPolicy` itself and thus the effects of
this policy specification are also same.

The raw specification of the resource in go looks like this:

.. code-block:: go

        type CiliumClusterwideNetworkPolicy struct {
                *CiliumNetworkPolicy

                // Status is the status of the Cilium policy rule
                // +optional
                // The reason this field exists in this structure is due a bug in the k8s code-generator
                // that doesn't create a `UpdateStatus` method because the field does not exist in
                // the structure.
                Status CiliumNetworkPolicyStatus `json:"status"`
        }
