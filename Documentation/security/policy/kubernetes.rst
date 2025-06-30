.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Using Kubernetes Constructs In Policy
=====================================

This section covers Kubernetes specific network policy aspects.

.. _k8s_namespaces:

Namespaces
----------

`Namespaces <https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/>`_
are used to create virtual clusters within a Kubernetes cluster. All Kubernetes objects
including `NetworkPolicy` and `CiliumNetworkPolicy` belong to a particular
namespace.

Known Pitfalls
--------------

This section covers known pitfalls when using Kubernetes constructs in policy.

Considerations Of Namespace Boundaries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Depending on how a policy is defined and created, Kubernetes namespaces are automatically taken into account.

Network policies imported directly with the :ref:`api_ref` apply to all
namespaces unless a namespace selector is specified as described in
:ref:`example_cnp_ns_boundaries`.

.. _example_cnp_ns_boundaries:

Example
^^^^^^^

This example demonstrates how to enforce Kubernetes namespace-based boundaries
for the namespaces ``ns1`` and ``ns2`` by enabling default-deny on all pods of
either namespace and then allowing communication from all pods within the same
namespace.

.. note:: The example locks down ingress of the pods in ``ns1`` and ``ns2``.
	  This means that the pods can still communicate egress to anywhere
	  unless the destination is in either ``ns1`` or ``ns2`` in which case
	  both source and destination have to be in the same namespace. In
	  order to enforce namespace boundaries at egress, the same example can
	  be used by specifying the rules at egress in addition to ingress.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/isolate-namespaces.yaml
          :language: yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/isolate-namespaces.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/isolate-namespaces.json

Policies Only Apply Within The Namespace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Network policies created and imported as `CiliumNetworkPolicy` CRD and
`NetworkPolicy` apply within the namespace. In other words, the policy **only** applies
to pods within that namespace. It's possible, however, to grant access to and
from pods in other namespaces as described in :ref:`example_cnp_across_ns`.

.. _example_cnp_across_ns:

Example
^^^^^^^

The following example exposes all pods with the label ``name=leia`` in the
namespace ``ns1`` to all pods with the label ``name=luke`` in the namespace
``ns2``.

Refer to the :git-tree:`example YAML files <examples/policies/kubernetes/namespace/demo-pods.yaml>`
for a fully functional example including pods deployed to different namespaces.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/namespace-policy.yaml
          :language: yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/namespace-policy.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/namespace-policy.json

Specifying Namespace In EndpointSelector, FromEndpoints, ToEndpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Specifying the namespace by way of the label
``k8s:io.kubernetes.pod.namespace`` in the ``fromEndpoints`` and
``toEndpoints`` fields is supported as described in 
:ref:`example_cnp_egress_to_kube_system`.
However, Kubernetes prohibits specifying the namespace in the ``endpointSelector``,
as it would violate the namespace isolation principle of Kubernetes. The
``endpointSelector`` always applies to pods in the namespace 
associated with the `CiliumNetworkPolicy` resource itself.

.. _example_cnp_egress_to_kube_system:

Example
^^^^^^^

The following example allows all pods in the ``public`` namespace in which the
policy is created to communicate with kube-dns on port 53/UDP in the ``kube-system``
namespace.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/kubedns-policy.yaml
          :language: yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/kubedns-policy.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/kubedns-policy.json


Namespace Specific Information
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using namespace-specific information like
``io.cilium.k8s.namespace.labels`` within a ``fromEndpoints`` or
``toEndpoints`` is supported only for a :ref:`CiliumClusterwideNetworkPolicy`
and not a :ref:`CiliumNetworkPolicy`. Hence, ``io.cilium.k8s.namespace.labels``
will be ignored in :ref:`CiliumNetworkPolicy` resources.

Match Expressions
~~~~~~~~~~~~~~~~~

When using ``matchExpressions`` in a :ref:`CiliumNetworkPolicy` or a
:ref:`CiliumClusterwideNetworkPolicy`, the list values are
treated as a logical AND. If you want to match multiple keys
with a logical OR, you must use multiple ``matchExpressions``.

.. _example_multiple_match_expressions:

Example
^^^^^^^

This example demonstrates how to enforce a policy with multiple ``matchExpressions``
that achieves a logical OR between the keys and its values.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/match-expressions/or-statement.yaml
          :language: yaml

     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/match-expressions/or-statement.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/match-expressions/or-statement.json


The following example shows a logical AND using a single ``matchExpression``.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/match-expressions/and-statement.yaml
          :language: yaml

     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/match-expressions/and-statement.json

ServiceAccounts
~~~~~~~~~~~~~~~

Kubernetes `Service Accounts
<https://kubernetes.io/docs/concepts/security/service-accounts/>`_ are used
to associate an identity to a pod or process managed by Kubernetes and grant
identities access to Kubernetes resources and secrets. Cilium supports the
specification of network security policies based on the service account
identity of a pod.

The service account of a pod is either defined via the `service account
admission controller
<https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#serviceaccount>`_
or can be directly specified in the Pod, Deployment, ReplicationController
resource like this:

.. code-block:: yaml

        apiVersion: v1
        kind: Pod
        metadata:
          name: my-pod
        spec:
          serviceAccountName: leia
          ...

Example
^^^^^^^

The following example grants any pod running under the service account of
"luke" to issue a ``HTTP GET /public`` request on TCP port 80 to all pods
running associated to the service account of "leia".

Refer to the :git-tree:`example YAML files <examples/policies/kubernetes/serviceaccount/demo-pods.yaml>`
for a fully functional example including deployment and service account
resources.


.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/serviceaccount/serviceaccount-policy.yaml
          :language: yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/kubernetes/serviceaccount/serviceaccount-policy.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/serviceaccount/serviceaccount-policy.json

Multi-Cluster
~~~~~~~~~~~~~

When operating multiple cluster with cluster mesh, the cluster name is exposed
via the label ``io.cilium.k8s.policy.cluster`` and can be used to restrict
policies to a particular cluster.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/clustermesh/cross-cluster-policy.yaml
          :language: yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/clustermesh/cross-cluster-policy.yaml
          :language: yaml

Note the ``io.kubernetes.pod.namespace: default`` in the policy
rule. It makes sure the policy applies to ``rebel-base`` in the
``default`` namespace of ``cluster2`` regardless of the namespace in
``cluster1`` where ``x-wing`` is deployed in.

If the namespace label of policy rules is omitted it defaults to the same namespace
where the policy itself is applied in, which may be not what is wanted when deploying
cross-cluster policies. To allow access from/to any namespace, use ``matchExpressions``
combined with an ``Exists`` operator.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/clustermesh/cross-cluster-any-namespace-policy.yaml
          :language: yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/clustermesh/cross-cluster-any-namespace-policy.yaml
          :language: yaml

Clusterwide Policies
~~~~~~~~~~~~~~~~~~~~

`CiliumNetworkPolicy` only allows to bind a policy restricted to a particular namespace. There can be situations
where one wants to have a cluster-scoped effect of the policy, which can be done using Cilium's
`CiliumClusterwideNetworkPolicy` Kubernetes custom resource. The specification of the policy is same as that
of `CiliumNetworkPolicy` except that it is not namespaced.

In the cluster, this policy will allow ingress traffic from pods matching the label ``name=luke`` from any
namespace to pods matching the labels ``name=leia`` in any namespace.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/clusterscope-policy.yaml
          :language: yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/clusterscope-policy.yaml
          :language: yaml

Allow All Cilium Managed Endpoints To Communicate With Kube-dns
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example allows all Cilium managed endpoints in the cluster to communicate
with kube-dns on port 53/UDP in the ``kube-system`` namespace.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/wildcard-from-endpoints.yaml
          :language: yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/wildcard-from-endpoints.yaml
          :language: yaml

.. _health_endpoint: 

Example: Add Health Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example adds the health entity to all Cilium managed endpoints in order to check
cluster connectivity health.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/health.yaml
          :language: yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/health.yaml
          :language: yaml
