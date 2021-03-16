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
      description: "Allow x-wing in cluster1 to contact rebel-base in cluster2"
      endpointSelector:
        matchLabels:
          name: x-wing
          io.cilium.k8s.policy.cluster: cluster1
      egress:
      - toEndpoints:
        - matchLabels:
            name: rebel-base
            io.cilium.k8s.policy.cluster: cluster2

Limitations
###########

 * L7 security policies currently only work across multiple clusters if worker
   nodes have routes installed allowing to route pod IPs of all clusters. This
   is obtained when running in direct routing mode by running a routing daemon or
   ``--auto-direct-node-routes`` but won't work automatically when using
   tunnel/encapsulation mode.
