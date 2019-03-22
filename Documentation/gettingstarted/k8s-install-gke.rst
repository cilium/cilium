.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

**************************
Installation on Google GKE
**************************

GKE Requirements
================

1. Install the Google Cloud SDK (``gcloud``) see [Installing Google Cloud SDK](https://cloud.google.com/sdk/install)

2. Create a project or use an existing one

::

   export GKE_PROJECT=gke-clusters
   gcloud projects create $GKE_PROJECT


3. Enable the GKE API for the project if not already done

::

   gcloud services enable --project $GKE_PROJECT container.googleapis.com

Create a GKE Cluster
====================

You can apply any method to create a GKE cluster. The example given here is
using the `Google Cloud SDK <https://cloud.google.com/sdk/>`_. This guide
will create a cluster on zone ``europe-west4-a``; feel free to change the zone
if you are in a different region of the globe.

.. code:: bash

    export GKE_ZONE="europe-west4-a"
    gcloud container --project $GKE_PROJECT clusters create cluster1 \
       --username "admin" --image-type COS --num-nodes 2 --zone ${GKE_ZONE}

When done, you should be able to access your cluster like this:

.. code:: bash

    kubectl get nodes
    NAME                                      STATUS   ROLES    AGE   VERSION
    gke-cluster1-default-pool-a63a765c-flr2   Ready    <none>   6m    v1.11.7-gke.4
    gke-cluster1-default-pool-a63a765c-z73c   Ready    <none>   6m    v1.11.7-gke.4

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

  .. group-tab:: K8s 1.14

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-with-node-init.yaml

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


Restart remaining pods
======================

Once Cilium is up and running, restart all pods in ``kube-system`` so they can
be managed by Cilium, similar to the steps that we have previously performed
for ``kube-dns``

::

    $ kubectl delete pods -n kube-system $(kubectl get pods -n kube-system -o custom-columns=NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork --no-headers=true | grep '<none>' | awk '{ print $1 }')
    pod "event-exporter-v0.2.3-f9c896d75-cbvcz" deleted
    pod "fluentd-gcp-scaler-69d79984cb-nfwwk" deleted
    pod "heapster-v1.6.0-beta.1-56d5d5d87f-qw8pv" deleted
    pod "kube-dns-5f8689dbc9-2nzft" deleted
    pod "kube-dns-5f8689dbc9-j7x5f" deleted
    pod "kube-dns-autoscaler-76fcd5f658-22r72" deleted
    pod "kube-state-metrics-7d9774bbd5-n6m5k" deleted
    pod "l7-default-backend-6f8697844f-d2rq2" deleted
    pod "metrics-server-v0.3.1-54699c9cc8-7l5w2" deleted
