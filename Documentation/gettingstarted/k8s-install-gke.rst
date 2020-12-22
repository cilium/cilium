.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_gke:

**************************
Installation on Google GKE
**************************

GKE Requirements
================

1. Install the Google Cloud SDK (``gcloud``) see `Installing Google Cloud SDK <https://cloud.google.com/sdk/install>`_.

2. Create a project or use an existing one

.. code:: bash

    export GKE_PROJECT=gke-clusters
    gcloud projects create $GKE_PROJECT
    gcloud config set project $GKE_PROJECT


3. Enable the GKE API for the project if not already done

.. code:: bash

    gcloud services enable container.googleapis.com

Create a GKE Cluster
====================

You can apply any method to create a GKE cluster. The example given here is
using the `Google Cloud SDK <https://cloud.google.com/sdk/>`_.

.. note:: Either of the cluster zone or region must be specified in ``gcloud``
          commands below. The full list of locations is available on
          `this page <https://cloud.google.com/compute/docs/regions-zones#locations>`_.
          This guide uses ``--zone`` to specify the zone but you may replace
          this flag with ``--region`` instead.

.. code:: bash

    export CLUSTER_NAME=cluster1
    export CLUSTER_ZONE=us-west2-a
    gcloud container clusters create $CLUSTER_NAME --image-type COS --num-nodes 2 --machine-type n1-standard-4 --zone $CLUSTER_ZONE

Retrieve the credentials to access the cluster:

.. code:: bash

    gcloud container clusters get-credentials $CLUSTER_NAME --zone $CLUSTER_ZONE

When done, you should be able to access your cluster like this:

.. code:: bash

    kubectl get nodes
    NAME                                      STATUS   ROLES    AGE   VERSION
    gke-cluster1-default-pool-a63a765c-flr2   Ready    <none>   6m    v1.14.10-gke.36
    gke-cluster1-default-pool-a63a765c-z73c   Ready    <none>   6m    v1.14.10-gke.36

Deploy Cilium
=============

Extract the Cluster CIDR to enable native-routing:

.. code:: bash

    NATIVE_CIDR="$(gcloud container clusters describe $CLUSTER_NAME --zone $CLUSTER_ZONE --format 'value(clusterIpv4Cidr)')"
    echo $NATIVE_CIDR

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

If you are ready to restart existing pods when initializing the node, you can
also pass the ``--set nodeinit.restartPods=true`` flag to the ``helm`` command
below. This will ensure all pods are managed by Cilium.

.. parsed-literal::

    kubectl create namespace cilium
    helm install cilium |CHART_RELEASE| \\
      --namespace cilium \\
      --set nodeinit.enabled=true \\
      --set nodeinit.reconfigureKubelet=true \\
      --set nodeinit.removeCbrBridge=true \\
      --set cni.binPath=/home/kubernetes/bin \\
      --set gke.enabled=true \\
      --set ipam.mode=kubernetes \\
      --set nativeRoutingCIDR=$NATIVE_CIDR

The NodeInit DaemonSet is required to prepare the GKE nodes as nodes are added
to the cluster. The NodeInit DaemonSet will perform the following actions:

* Reconfigure kubelet to run in CNI mode
* Mount the eBPF filesystem

.. include:: k8s-install-restart-pods.rst
.. include:: k8s-install-gke-validate.rst
.. include:: namespace-cilium.rst
.. include:: hubble-enable.rst

