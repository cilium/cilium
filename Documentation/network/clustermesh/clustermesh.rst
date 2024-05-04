.. _clustermesh:
.. _gs_clustermesh:

***********************
Setting up Cluster Mesh
***********************

This is a step-by-step guide on how to build a mesh of Kubernetes clusters by
connecting them together, enable pod-to-pod connectivity across all clusters,
define global services to load-balance between clusters and enforce security
policies to restrict access.

.. admonition:: Video
  :class: attention

  Aside from this step-by-step guide, if you would like to watch how Cilium's
  Clustermesh feature works, check out `eCHO Episode 41: Cilium Clustermesh <https://www.youtube.com/watch?v=VBOONHW65NU&t=342s>`__.

Prerequisites
#############

Cluster Addressing Requirements
===============================

* All clusters must be configured with the same datapath mode. Cilium install
  may default to :ref:`arch_overlay` or :ref:`native_routing` mode depending on
  the specific cloud environment.

* PodCIDR ranges in all clusters and all nodes must be non-conflicting and
  unique IP addresses.

* Nodes in all clusters must have IP connectivity between each other using the 
  configured InternalIP for each node. This requirement is typically met by establishing 
  peering or VPN tunnels between the networks of the nodes of each cluster.

* The network between clusters must allow the inter-cluster communication. The
  exact ports are documented in the :ref:`firewall_requirements` section.

.. note::
  
  For cloud-specific deployments, you can check out the :ref:`gs_clustermesh_aks_prep`
  guide for Azure Kubernetes Service (AKS), the :ref:`gs_clustermesh_eks_prep`
  guide for Amazon Elastic Kubernetes Service (EKS) or the :ref:`gs_clustermesh_gke_prep` 
  guide for Google Kubernetes Engine (GKE) clusters for instructions on
  how to meet the above requirements.

Additional Requirements for Native-routed Datapath Modes
--------------------------------------------------------

* Cilium in each cluster must be configured with a native routing CIDR that
  covers all the PodCIDR ranges across all connected clusters. Cluster CIDRs are
  typically allocated from the ``10.0.0.0/8`` private address space. When this
  is the case a native routing CIDR such as ``10.0.0.0/8`` should cover all
  clusters:

 * ConfigMap option ``ipv4-native-routing-cidr=10.0.0.0/8``
 * Helm option ``--set ipv4NativeRoutingCIDR=10.0.0.0/8``
 * ``cilium install`` option ``--set ipv4NativeRoutingCIDR=10.0.0.0/8``

* In addition to nodes, pods in all clusters must have IP connectivity between each other. This
  requirement is typically met by establishing peering or VPN tunnels between
  the networks of the nodes of each cluster

* The network between clusters must allow pod-to-pod inter-cluster communication
  across any ports that the pods may use. This is typically accomplished with
  firewall rules allowing pods in different clusters to reach each other on all
  ports.

Scaling Limitations
=============================

* By default, the maximum number of clusters that can be connected together using Cluster Mesh is
  255. By using the option ``maxConnectedClusters`` this limit can be set to 511, at the expense of
  lowering the maximum number of cluster-local identities. Reference the following table for valid
  configurations and their corresponding cluster-local identity limits:

+------------------------+------------+----------+----------+
| MaxConnectedClusters   | Maximum cluster-local identities |
+========================+============+==========+==========+
| 255 (default)          | 65535                            |
+------------------------+------------+----------+----------+
| 511                    | 32767                            |
+------------------------+------------+----------+----------+

* All clusters across a Cluster Mesh must be configured with the same ``maxConnectedClusters``
  value.

 * ConfigMap option ``max-connected-clusters=511``
 * Helm option ``--set clustermesh.maxConnectedClusters=511``
 * ``cilium install`` option ``--set clustermesh.maxConnectedClusters=511``

.. note::

   This option controls the bit allocation of numeric identities and will affect the maximum number
   of cluster-local identities that can be allocated. By default, cluster-local
   :ref:`security_identities` are limited to 65535, regardless of whether Cluster Mesh is used or
   not.

.. warning::
  ``MaxConnectedClusters`` can only be set once during Cilium installation and should not be
  changed for existing clusters. Changing this option on a live cluster may result in connection
  disruption and possible incorrect enforcement of network policies

Install the Cilium CLI
======================

.. include:: ../../installation/cli-download.rst

.. warning::

  Don't use the Cilium CLI *helm* mode to enable Cluster Mesh or connect clusters
  configured using the Cilium CLI operating in *classic* mode, as the two modes are
  not compatible with each other.

Prepare the Clusters
####################

For the rest of this tutorial, we will assume that you intend to connect two
clusters together with the kubectl configuration context stored in the
environment variables ``$CLUSTER1`` and ``$CLUSTER2``. This context name is the
same as you typically pass to ``kubectl --context``.

Specify the Cluster Name and ID
===============================

Cilium needs to be installed onto each cluster.

Each cluster must be assigned a unique human-readable name as well as a numeric
cluster ID (1-255). It is best to assign both these attributes at installation
time of Cilium:

 * ConfigMap options ``cluster-name`` and ``cluster-id``
 * Helm options ``cluster.name`` and ``cluster.id``
 * Cilium CLI install options ``--set cluster.name`` and ``--set cluster.id``

Review :ref:`k8s_install_quick` for more details and use cases.

Example install using the Cilium CLI:

.. code-block:: shell-session

  cilium install --set cluster.name=$CLUSTER1 --set cluster.id=1 --context $CLUSTER1
  cilium install --set cluster.name=$CLUSTER2 --set cluster.id=2 --context $CLUSTER2

.. important::

   If you change the cluster ID and/or cluster name in a cluster with running
   workloads, you will need to restart all workloads. The cluster ID is used to
   generate the security identity and it will need to be re-created in order to
   establish access across clusters.

Shared Certificate Authority
============================

If you are planning to run Hubble Relay across clusters, it is best to share a
certificate authority (CA) between the clusters as it will enable mTLS across
clusters to just work.

You can propagate the CA copying the Kubernetes secret containing the CA
from one cluster to another:

.. code-block:: shell-session

  kubectl --context=$CLUSTER1 get secret -n kube-system cilium-ca -o yaml | \
    kubectl --context $CLUSTER2 create -f -

.. _enable_clustermesh:

Enable Cluster Mesh
===================

Enable all required components by running ``cilium clustermesh enable`` in the
context of both clusters. This will deploy the ``clustermesh-apiserver`` into
the cluster and generate all required certificates and import them as
Kubernetes secrets. It will also attempt to auto-detect the best service type
for the LoadBalancer to expose the Cluster Mesh control plane to other
clusters.

.. code-block:: shell-session

   cilium clustermesh enable --context $CLUSTER1
   cilium clustermesh enable --context $CLUSTER2

.. note::

   You can additionally opt in to :ref:`kvstoremesh` when enabling
   Cluster Mesh. Make sure to configure the Cilium CLI in *helm* mode and run:

   .. code-block:: shell-session

     cilium clustermesh enable --context $CLUSTER1 --enable-kvstoremesh
     cilium clustermesh enable --context $CLUSTER2 --enable-kvstoremesh

.. important::

   In some cases, the service type cannot be automatically detected and you need to specify it manually. This
   can be done with the option ``--service-type``. The possible values are:

   LoadBalancer:
     A Kubernetes service of type LoadBalancer is used to expose the control
     plane. This uses a stable LoadBalancer IP and is typically the best option. 

   NodePort:
     A Kubernetes service of type NodePort is used to expose the control plane.
     This requires stable Node IPs. If a node disappears, the Cluster Mesh may
     have to reconnect to a different node. If all nodes have become
     unavailable, you may have to re-connect the clusters to extract new node
     IPs.

   ClusterIP:
     A Kubernetes service of type ClusterIP is used to expose the control
     plane. This requires the ClusterIPs are routable between clusters.

Wait for the Cluster Mesh components to come up by invoking ``cilium
clustermesh status --wait``. If you are using a service of type LoadBalancer
then this will also wait for the LoadBalancer to be assigned an IP.

.. code-block:: shell-session

   cilium clustermesh status --context $CLUSTER1 --wait
   cilium clustermesh status --context $CLUSTER2 --wait

.. code-block:: shell-session

    ✅ Cluster access information is available:
      - 10.168.0.89:2379
    ✅ Service "clustermesh-apiserver" of type "LoadBalancer" found
    🔌 Cluster Connections:
    🔀 Global services: [ min:0 / avg:0.0 / max:0 ]


Connect Clusters
================

Finally, connect the clusters. This step only needs to be done in one
direction. The connection will automatically be established in both directions:

.. code-block:: shell-session

    cilium clustermesh connect --context $CLUSTER1 --destination-context $CLUSTER2

It may take a bit for the clusters to be connected. You can run ``cilium
clustermesh status --wait`` to wait for the connection to be successful:

.. code-block:: shell-session

   cilium clustermesh status --context $CLUSTER1 --wait

The output will look something like this:

.. code-block:: shell-session

    ✅ Cluster access information is available:
      - 10.168.0.89:2379
    ✅ Service "clustermesh-apiserver" of type "LoadBalancer" found
    ⌛ Waiting (12s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (25s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (38s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (51s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (1m4s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (1m17s) for clusters to be connected: 1 nodes are not ready
    ✅ All 2 nodes are connected to all clusters [min:1 / avg:1.0 / max:1]
    🔌 Cluster Connections:
    - cilium-cli-ci-multicluster-2-168: 2/2 configured, 2/2 connected
    🔀 Global services: [ min:6 / avg:6.0 / max:6 ]

If this step does not complete successfully, proceed to the troubleshooting
section.

Test Pod Connectivity Between Clusters
======================================

Congratulations, you have successfully connected your clusters together. You
can validate the connectivity by running the connectivity test in multi cluster
mode:

.. code-block:: shell-session

   cilium connectivity test --context $CLUSTER1 --multi-cluster $CLUSTER2

Next Steps
==========

Logical next steps to explore from here are:

 * :ref:`gs_clustermesh_services`
 * :ref:`gs_clustermesh_network_policy`

Troubleshooting
###############

Use the following list of steps to troubleshoot issues with ClusterMesh:

 #. Validate that the ``cilium-xxx`` as well as the ``cilium-operator-xxx`` pods
    are healthy and ready. 

    .. code-block:: shell-session

       cilium status --context $CLUSTER1
       cilium status --context $CLUSTER2

 #. Validate the Cluster Mesh is enabled correctly and operational:

    .. code-block:: shell-session

       cilium clustermesh status --context $CLUSTER1
       cilium clustermesh status --context $CLUSTER2

If you cannot resolve the issue with the above commands, see the
:ref:`troubleshooting_clustermesh` for a more detailed troubleshooting guide.
