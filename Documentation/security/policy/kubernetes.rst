.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Using Kubernetes Constructs in Policy
=====================================

This section covers Kubernetes specific network policy aspects.

.. _k8s_namespaces:

Namespaces
----------

`Namespaces <https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/>`_
are used to create virtual clusters within a Kubernetes cluster. All Kubernetes objects
including NetworkPolicy and CiliumNetworkPolicy belong to a particular
namespace. Depending on how a policy is being defined and created, Kubernetes
namespaces are automatically being taken into account:

* Network policies created and imported as `CiliumNetworkPolicy` CRD and
  `NetworkPolicy` apply within the namespace, i.e. the policy only applies
  to pods within that namespace. It is however possible to grant access to and
  from pods in other namespaces as described below.

* Network policies imported directly via the :ref:`api_ref` apply to all
  namespaces unless a namespace selector is specified as described below.

.. note:: While specification of the namespace via the label
	  ``k8s:io.kubernetes.pod.namespace`` in the ``fromEndpoints`` and
	  ``toEndpoints`` fields is deliberately supported. Specification of the
	  namespace in the ``endpointSelector`` is prohibited as it would
	  violate the namespace isolation principle of Kubernetes. The
	  ``endpointSelector`` always applies to pods of the namespace which is
	  associated with the CiliumNetworkPolicy resource itself.

Example: Enforce namespace boundaries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/isolate-namespaces.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/isolate-namespaces.json

Example: Expose pods across namespaces
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example exposes all pods with the label ``name=leia`` in the
namespace ``ns1`` to all pods with the label ``name=luke`` in the namespace
``ns2``.

Refer to the :git-tree:`example YAML files <examples/policies/kubernetes/namespace/demo-pods.yaml>`
for a fully functional example including pods deployed to different namespaces.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/namespace-policy.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/namespace-policy.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/namespace-policy.json

Example: Allow egress to kube-dns in kube-system namespace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example allows all pods in the ``public`` namespace in which the
policy is created to communicate with kube-dns on port 53/UDP in the ``kube-system``
namespace.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/kubedns-policy.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/kubedns-policy.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/namespace/kubedns-policy.json


ServiceAccounts
----------------

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
~~~~~~~

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
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/kubernetes/serviceaccount/serviceaccount-policy.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/serviceaccount/serviceaccount-policy.json

Multi-Cluster
-------------

When operating multiple cluster with cluster mesh, the cluster name is exposed
via the label ``io.cilium.k8s.policy.cluster`` and can be used to restrict
policies to a particular cluster.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/clustermesh/cross-cluster-policy.yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/clustermesh/cross-cluster-policy.yaml

Note the ``io.kubernetes.pod.namespace: default`` in the policy
rule. It makes sure the policy applies to ``rebel-base`` in the
``default`` namespace of ``cluster2`` regardless of the namespace in
``cluster1`` where ``x-wing`` is deployed in. If the namespace label
of policy rules is omitted it defaults to the same namespace where the
policy itself is applied in, which may be not what is wanted when
deploying cross-cluster policies.

Clusterwide Policies
--------------------

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

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/clusterscope-policy.yaml

Example: Allow all ingress to kube-dns
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example allows all Cilium managed endpoints in the cluster to communicate
with kube-dns on port 53/UDP in the ``kube-system`` namespace.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/wildcard-from-endpoints.yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/wildcard-from-endpoints.yaml

.. _health_endpoint:

Example: Add health endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example adds the health entity to all Cilium managed endpoints in order to check
cluster connectivity health.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/health.yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/kubernetes/clusterwide/health.yaml
