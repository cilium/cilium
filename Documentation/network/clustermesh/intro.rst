.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _Cluster Mesh:

############################
Multi-Cluster (Cluster Mesh)
############################

Cluster mesh extends the networking datapath across multiple clusters. It
allows endpoints in all connected clusters to communicate while providing full
policy enforcement. Load-balancing is available via Kubernetes annotations.

See :ref:`gs_clustermesh` for instructions on how to set up cluster mesh.

.. _kvstoremesh:

KVStoreMesh (beta)
==================

.. include:: ../../beta.rst

KVStoreMesh is an extension of Cluster Mesh. It caches the information obtained
from the remote clusters in a local kvstore (such as etcd), to which all local
Cilium agents connect. This is different from vanilla Cluster Mesh, where each
agent directly pulls the information from the remote clusters. KVStoreMesh enables
improved scalability and isolation, and targets large scale Cluster Mesh deployments.

See :ref:`enable_clustermesh` for instructions on how to enable KVStoreMesh.
