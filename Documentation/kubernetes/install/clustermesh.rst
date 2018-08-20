.. _clustermesh:

****************************
Setting up the Cluster Mesh
****************************

This is a step-by-step guide on how to build a mesh of Kubernetes clusters by
connecting them together and enabling pod-to-pod connectivity across all
clusters while providing label-based security policies.

.. note::

    This is a beta feature introduced in Cilium 1.2.

Prerequisites
#############

* All nodes in all clusters must have IP connectivity. This requirement is
  typically met by establishing peering between the networks of the machines
  forming each cluster.

* No encryption is performed by Cilium for the connectivity between nodes.
  The feature is on the roadmap (`details
  <https://github.com/cilium/cilium/issues/504>`_) but not implemented yet.  It
  is however possible to set up IPSec-based encryption between all nodes using
  a standard guide. It is also possible and common to establish VPNs between
  networks if clusters are connected across untrusted networks.

* All worker nodes must have connectivity to the etcd clusters of all remote
  clusters. Security is implemented by connecting to etcd using TLS/SSL
  certificates.

* Cilium must be configured to use etcd as the kvstore. Consul is not supported
  by cluster mesh.

Getting Started
###############

Step 1: Prepare the individual clusters
=======================================

Setting the cluster name and ID
-------------------------------

Each cluster must be assigned a unique human-readable name. The name will be
used to group nodes of a cluster. The cluster name is specified with the
``--cluster-name=NAME`` argument or ``cluster-name`` ConfigMap option.

To ensure scalability of identity allocation and policy enforcement, each
cluster continues to manage its own identity allocation. In order to guarantee
compatibility with identities across clusters, each cluster is configured with
a unique cluster ID configured with the ``--cluster-id=ID`` argument or
``cluster-id`` ConfigMap option.

.. code:: bash

   $ kubectl -n kube-system edit cm cilium-config
   [ add/edit ]
   cluster-name: default
   cluster-id: 1

Provide unique values for the cluster name and ID for each cluster.

Step 2: Create Secret to provide access to remote etcd
------------------------------------------------------

Clusters are connected together by providing connectivity information to the
etcd key-value store to each individual cluster. This allows Cilium to
synchronize state between clusters and provide cross-cluster connectivity and
policy enforcement.

The connectivity details of a remote etcd typically includes certificates to
enable use of TLS which is why the entire ClusterMesh configuration is stored
in a Kubernetes Secret.

1. Create an etcd configuration file for each remote cluster you want to
   connect to. The syntax is that the official etcd configuration file and
   identical to the syntax used in the ``cilium-config`` ConfigMap.

2. Create a secret ``cilium-clustermesh`` from all configuration files you have
   created:

   .. code:: bash

       $ ks create secret generic cilium-clustermesh --from-file=./cluster5 --from-file=./cluster7

   Cilium will automatically ignore any configuration referring to its own
   cluster so you can create a single secret and import it into all your
   clusters to establish connectivity between all clusters.

   .. code:: bash

       cluster 1:
       $ kubectl -n kube-system get secret cilium-clustermesh -o yaml > clustermesh.yaml

       cluster 2:
       $ kubectl apply -f clustermesh.yaml

Step 3: Restart the cilium agent
--------------------------------

Restart Cilium in each cluster to pick up the new cluster name, cluster id and
clustermesh secret configuration. Cilium will automatically establish
connectivity between the clusters.

.. code:: bash

    $ kubectl -n kube-system delete -l k8s-app=cilium

Step 4: Test the connectivity between clusters
----------------------------------------------

Run ``cilium node list`` to see the full list of nodes discovered. You can run
this command inside any Cilium pod in any cluster:

.. code:: bash

    $ kubectl -n kube-system exec -ti cilium-g6btl cilium node list
    Name                                                   IPv4 Address    Endpoint CIDR   IPv6 Address   Endpoint CIDR
    cluster5/ip-172-0-117-60.us-west-2.compute.internal    172.0.117.60    10.2.2.0/24     <nil>          f00d::a02:200:0:0/112
    cluster5/ip-172-0-186-231.us-west-2.compute.internal   172.0.186.231   10.2.3.0/24     <nil>          f00d::a02:300:0:0/112
    cluster5/ip-172-0-50-227.us-west-2.compute.internal    172.0.50.227    10.2.0.0/24     <nil>          f00d::a02:0:0:0/112
    cluster5/ip-172-0-51-175.us-west-2.compute.internal    172.0.51.175    10.2.1.0/24     <nil>          f00d::a02:100:0:0/112
    cluster7/ip-172-0-121-242.us-west-2.compute.internal   172.0.121.242   10.4.2.0/24     <nil>          f00d::a04:200:0:0/112
    cluster7/ip-172-0-58-194.us-west-2.compute.internal    172.0.58.194    10.4.1.0/24     <nil>          f00d::a04:100:0:0/112
    cluster7/ip-172-0-60-118.us-west-2.compute.internal    172.0.60.118    10.4.0.0/24     <nil>          f00d::a04:0:0:0/112


.. code:: bash

    $ kubectl exec -ti pod-cluster5-xxx curl <pod-ip-cluster7>
    [...]
