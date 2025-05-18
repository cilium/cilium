.. _gs_clustermesh_network_policy:

**************
Network Policy
**************

This tutorial will guide you how to define NetworkPolicies affecting multiple
clusters.

Prerequisites
#############

You need to have a functioning Cluster Mesh setup, please follow the guide
:ref:`gs_clustermesh` to set it up.

Security Policies
#################

As addressing and network security are decoupled, network security enforcement
automatically spans across clusters. Note that Kubernetes security policies are
not automatically distributed across clusters, it is your responsibility to
apply ``CiliumNetworkPolicy`` or ``NetworkPolicy`` in all clusters.

Allowing Specific Communication Between Clusters
================================================

The following policy illustrates how to allow particular pods to communicate
between two clusters. The cluster name refers to the name given via the
``--cluster-name`` agent option or ``cluster-name`` ConfigMap option.

.. code-block:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: "allow-cross-cluster"
    spec:
      description: "Allow x-wing to be deployed in the local cluster to contact rebel-base in cluster2"
      endpointSelector:
        matchLabels:
          name: x-wing
      egress:
      - toEndpoints:
        - matchLabels:
            name: rebel-base
            io.cilium.k8s.policy.cluster: cluster2


Note that by default policies automatically select endpoints from all the clusters unless it is explicitly specified.
To restrict endpoint selection to the local cluster by default you can enable the option ``--policy-default-local-cluster``
via the ConfigMap option ``policy-default-local-cluster`` or the Helm value ``clustermesh.policyDefaultLocalCluster``.

The following policy illustrates how to explicitly allow pods to communicate to all clusters.

.. code-block:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: "allow-cross-cluster-any"
    spec:
      description: "Allow x-wing to be deployed in the local cluster to contact rebel-base in any cluster"
      endpointSelector:
        matchLabels:
          name: x-wing
      egress:
      - toEndpoints:
        - matchLabels:
            name: rebel-base
          matchExpressions:
            - key: io.cilium.k8s.policy.cluster
              operator: Exists
