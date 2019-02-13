.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

**************************
Installation on Google GKE
**************************

Create a GKE Cluster
====================

You can apply any method to create a GKE cluster. The example given here is
using the `Google Cloud SDK <https://cloud.google.com/sdk/>`_. 

.. code:: bash

    gcloud container --project gke-clusters clusters create cluster1 \
       --username "admin" --image-type COS --num-nodes 2

When done, you should be able to access your cluster like this:

.. code:: bash

    kubectl get nodes
    NAME                                      STATUS   ROLES    AGE   VERSION
    gke-cluster1-default-pool-c1b66ca9-7n7r   Ready    <none>   1h    v1.11.6-gke.3
    gke-cluster1-default-pool-c1b66ca9-8g3q   Ready    <none>   1h    v1.11.6-gke.3
    gke-cluster1-default-pool-c1b66ca9-tqs3   Ready    <none>   1h    v1.11.6-gke.3

Create a cluster-admin-binding
==============================

.. code:: bash

    kubectl create clusterrolebinding cluster-admin-binding --clusterrole cluster-admin --user your@google.email

Prepare the Cluster Nodes
=========================

By deploying the ``cilium-node-init`` DaemonSet, GKE worker nodes are
automatically prepared to run Cilium as they are added to the cluster. The
DaemonSet will:

* Mount the BPF filesystem
* Enable kubelet to operate in CNI mode
* Install the Cilium CNI configuration file

.. parsed-literal::

     kubectl create namespace cilium
     kubectl -n cilium apply -f \ |SCM_WEB|\/examples/kubernetes/node-init/node-init.yaml

Restart kube-dns
================

kube-dns is already running but is still managed by the original GKE network
plugin. Restart kube-dns to ensure it is managed by Cilium.

.. code:: bash

     kubectl -n kube-system delete pod -l k8s-app=kube-dns


Deploy Cilium + cilium-etcd-operator
====================================

The following all-in-one YAML will deploy all required components to bring up
Cilium including an etcd cluster managed by the cilium-etcd-operator.

.. tabs::
  .. group-tab:: K8s 1.13

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-with-node-init.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-with-node-init.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-with-node-init.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-with-node-init.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-with-node-init.yaml

  .. group-tab:: K8s 1.8

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-with-node-init.yaml
