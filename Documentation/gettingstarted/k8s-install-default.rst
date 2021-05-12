.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_quick:
.. _k8s_quick_install:
.. _k8s_install_standard:

******************
Quick Installation
******************

This guide will walk you through the quick default installation. It will
automatically detect and use the best configuration possible for the Kubernetes
distribution you are using. All state is stored using Kubernetes CRDs.

This is the best installation method for most use cases.  For large
environments (> 500 nodes) or if you want to run specific datapath modes, refer
to the :ref:`k8s_install_advanced` guide.

Should you encounter any issues during the installation, please refer to the
:ref:`troubleshooting_k8s` section and / or seek help on the `Slack channel`.

Create the Cluster
===================

If you don't have a Kubernetes Cluster yet, you can use the instructions below
to create a Kubernetes cluster locally or using a managed Kubernetes service:

.. tabs::

    .. group-tab:: GKE

       The following command creates a Kubernetes cluster using `Google
       Kubernetes Engine <https://cloud.google.com/kubernetes-engine>`_.  See
       `Installing Google Cloud SDK <https://cloud.google.com/sdk/install>`_
       for instructions on how to install ``gcloud`` and prepare your
       account.

       .. code-block:: shell-session

           export NAME="$(whoami)-$RANDOM"
           gcloud container clusters create "${NAME}" --zone us-west2-a 
           gcloud container clusters get-credentials "${NAME}" --zone us-west2-a

    .. group-tab:: AKS

       The following command creates a Kubernetes cluster using `Azure
       Kubernetes Service <https://docs.microsoft.com/en-us/azure/aks/>`_. See
       `Azure Cloud CLI
       <https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest>`_
       for instructions on how to install ``az`` and prepare your account.

       .. code-block:: shell-session

           export NAME="$(whoami)-$RANDOM"
           export AZURE_RESOURCE_GROUP="aks-cilium-group"
           az group create --name "${AZURE_RESOURCE_GROUP}" -l westus2
           az aks create --resource-group "${AZURE_RESOURCE_GROUP}" --name "${NAME}" --network-plugin azure
           az aks get-credentials --name "${NAME}" --resource-group "${AZURE_RESOURCE_GROUP}"

       .. attention::

           Do NOT specify the ``--network-policy`` flag when creating the
           cluster, as this will cause the Azure CNI plugin to install unwanted
           iptables rules.

    .. group-tab:: EKS

       The following command creates a Kubernetes cluster with ``eksctl``
       using `Amazon Elastic Kubernetes Service
       <https://aws.amazon.com/eks/>`_.  See `eksctl Installation
       <https://github.com/weaveworks/eksctl>`_ for instructions on how to
       install ``eksctl`` and prepare your account.

       .. code-block:: shell-session

           export NAME="$(whoami)-$RANDOM"
           eksctl create cluster --name "${NAME}" --region eu-west-1 --without-nodegroup

    .. group-tab:: kind

       Install ``kind`` >= v0.7.0 per kind documentation:
       `Installation and Usage <https://kind.sigs.k8s.io/#installation-and-usage>`_

       .. parsed-literal::

          curl -LO \ |SCM_WEB|\/Documentation/gettingstarted/kind-config.yaml
          kind create cluster --config=kind-config.yaml

    .. group-tab:: minikube

       Install minikube >= v1.5.2 as per minikube documentation: 
       `Install Minikube <https://kubernetes.io/docs/tasks/tools/install-minikube/>`_.

       .. code-block:: shell-session

          minikube start --network-plugin=cni

Install the Cilium CLI
======================

.. include:: cli-download.rst

Install Cilium
==============

You can install Cilium on any Kubernetes cluster. Pick one of the options below:

.. tabs::

    .. group-tab:: Generic

       These are the generic instructions on how to install Cilium into any
       Kubernetes cluster. The installer will attempt to automatically pick the
       best configuration options for you. Please see the other tabs for
       distribution/platform specific instructions which also list the ideal
       default configuration for particular platforms.

       .. include:: requirements-generic.rst

       **Install Cilium**

       Install Cilium into the Kubernetes cluster pointed to by your current kubectl context:

       .. code-block:: shell-session

          cilium install

    .. group-tab:: GCP/GKE

       .. include:: requirements-gke.rst

       **Install Cilium:**

       Install Cilium into the GKE cluster:

       .. code-block:: shell-session

           cilium install

    .. group-tab:: Azure/AKS

       .. include:: requirements-aks.rst

       **Install Cilium:**

       Install Cilium into the AKS cluster:

       .. code-block:: shell-session

           cilium install --azure-resource-group "${AZURE_RESOURCE_GROUP}"

    .. group-tab:: AWS/EKS

       .. include:: requirements-eks.rst

       **Install Cilium:**

       Install Cilium into the EKS cluster. Set ``--wait=false`` as no nodes
       exist yet. Then scale up the number of nodes and wait for Cilium to
       bootstrap successfully.

       .. code-block:: shell-session

           cilium install --wait=false
           eksctl create nodegroup --cluster "${NAME}" --region eu-west-1 --nodes 2 
           cilium status --wait

    .. group-tab:: OpenShift

       .. include:: requirements-openshift.rst

       **Install Cilium:**

       Cilium is a `Certified OpenShift CNI Plugin <https://access.redhat.com/articles/5436171>`_
       and is best installed when an OpenShift cluster is created using the OpenShift
       installer. Please refer to :ref:`k8s_install_openshift_okd` for more information.

    .. group-tab:: RKE

       .. include:: requirements-rke.rst

       **Install Cilium:**

       Install Cilium into your newly created RKE cluster:

       .. code-block:: shell-session

           cilium install

    .. group-tab:: k3s

       .. include:: requirements-k3s.rst
      
       **Install Cilium:**

       Install Cilium into your newly created Kubernetes cluster:

       .. code-block:: shell-session

           cilium install


If the installation fails for some reason, run ``cilium status`` to retrieve
the overall status of the Cilium deployment and inspect the logs of whatever
pods are failing to be deployed.

.. tip::

   You may be seeing ``cilium install`` print something like this:

   .. code-block:: shell-session

       ♻️  Restarted unmanaged pod kube-system/event-exporter-gke-564fb97f9-rv8hg
       ♻️  Restarted unmanaged pod kube-system/kube-dns-6465f78586-hlcrz
       ♻️  Restarted unmanaged pod kube-system/kube-dns-autoscaler-7f89fb6b79-fsmsg
       ♻️  Restarted unmanaged pod kube-system/l7-default-backend-7fd66b8b88-qqhh5
       ♻️  Restarted unmanaged pod kube-system/metrics-server-v0.3.6-7b5cdbcbb8-kjl65
       ♻️  Restarted unmanaged pod kube-system/stackdriver-metadata-agent-cluster-level-6cc964cddf-8n2rt

   This indicates that your cluster was already running some pods before Cilium
   was deployed and the installer has automatically restarted them to ensure
   all pods get networking provided by Cilium.

Validate the Installation
=========================

.. include:: cli-status.rst
.. include:: cli-connectivity-test.rst

.. include:: next-steps.rst
