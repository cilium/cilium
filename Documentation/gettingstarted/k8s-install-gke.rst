.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _k8s_install_gke:

**************************
Installation on Google GKE
**************************

GKE Requirements
================

1. Install the Google Cloud SDK (``gcloud``) see `Installing Google Cloud SDK <https://cloud.google.com/sdk/install>`_.

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
       --username admin --image-type COS --num-nodes 2 --zone ${GKE_ZONE}

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

Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

If you are ready to restart existing pods when initializing the node, you can
also pass the ``--set nodeinit.restartPods`` flag to the ``helm`` command
below. This will ensure all pods are managed by Cilium.

.. parsed-literal::

    kubectl create namespace cilium
    helm install cilium |CHART_RELEASE| \\
      --namespace cilium \\
      --set global.nodeinit.enabled=true \\
      --set nodeinit.reconfigureKubelet=true \\
      --set nodeinit.removeCbrBridge=true \\
      --set global.cni.binPath=/home/kubernetes/bin

The NodeInit DaemonSet is required to prepare the GKE nodes as nodes are added
to the cluster. The NodeInit DaemonSet will perform the following actions:

* Reconfigure kubelet to run in CNI mode
* Mount the BPF filesystem

.. include:: k8s-install-restart-pods.rst
.. include:: k8s-install-gke-validate.rst
.. include:: hubble-install.rst
.. include:: getting-started-next-steps.rst

