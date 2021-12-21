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

       .. code-block:: bash

           export NAME="$(whoami)-$RANDOM"
           # Create the node pool with the following taint to guarantee that
           # Pods are only scheduled in the node when Cilium is ready.
           gcloud container clusters create "${NAME}" \
            --node-taints node.cilium.io/agent-not-ready=true:NoSchedule \
            --zone us-west2-a
           gcloud container clusters get-credentials "${NAME}" --zone us-west2-a

    .. group-tab:: AKS

       The following command creates a Kubernetes cluster using `Azure
       Kubernetes Service <https://docs.microsoft.com/en-us/azure/aks/>`_. See
       `Azure Cloud CLI
       <https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest>`_
       for instructions on how to install ``az`` and prepare your account.

       .. code-block:: bash

           export NAME="$(whoami)-$RANDOM"
           export AZURE_RESOURCE_GROUP="aks-cilium-group"
           az group create --name "${AZURE_RESOURCE_GROUP}" -l westus2

           # Details: Basic load balancers are not supported with multiple node
           # pools. Create a cluster with standard load balancer selected to use
           # multiple node pools, learn more at aka.ms/aks/nodepools.
           az aks create \
           --resource-group "${AZURE_RESOURCE_GROUP}" \
           --name "${NAME}" \
           --network-plugin azure \
           --load-balancer-sku standard

           # Get the name of the node pool that was just created since it will
           # be deleted after Cilium is installed.
           nodepool_to_delete=$(az aks nodepool list --cluster-name "${NAME}" -g "${AZURE_RESOURCE_GROUP}" -o json | jq -r '.[0].name')

           # Create a node pool with 'mode=system' as it is the same mode used
           # for the default nodepool on cluster creation also this new node
           # pool will have the taint 'node.cilium.io/agent-not-ready=true:NoSchedule'
           # which will guarantee that pods will only be scheduled on that node
           # once Cilium is ready.
           az aks nodepool add \
             --name "nodepool2" \
             --cluster-name "${NAME}" \
             --resource-group "${AZURE_RESOURCE_GROUP}" \
             --node-count 2 \
             --mode system \
             --node-taints node.cilium.io/agent-not-ready=true:NoSchedule

           # Get the credentials to access the cluster with kubectl
           az aks get-credentials --name "${NAME}" --resource-group "${AZURE_RESOURCE_GROUP}"

           # We can only delete the first node pool after Cilium is installed
           # because some pods have Pod Disruption Budgets set. If we try to
           # delete the first node pool without the second node pool being ready,
           # AKS will not succeed with the pool deletion because some Deployments
           # can't cease to exist in the cluster.
           #
           # NOTE: Only delete the nodepool after deploying Cilium
           az aks nodepool delete --name ${nodepool_to_delete} \
             --cluster-name "${NAME}" \
             --resource-group "${AZURE_RESOURCE_GROUP}"

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
           cat <<EOF >eks-config.yaml
           apiVersion: eksctl.io/v1alpha5
           kind: ClusterConfig

           metadata:
             name: ${NAME}
             region: eu-west-1

           managedNodeGroups:
           - name: ng-1
             desiredCapacity: 2
             privateNetworking: true
             # taint nodes so that application pods are
             # not scheduled until Cilium is deployed.
             taints:
              - key: "node.cilium.io/agent-not-ready"
                value: "true"
                effect: "NoSchedule"
           EOF
           eksctl create cluster -f ./eks-config.yaml

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

    .. note::

       From minikube v1.12.1+, cilium networking plugin can be enabled directly with
       ``--cni=cilium`` parameter in ``minikube start`` command. However, this may not
       install the latest version of cilium.

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

       Install Cilium into the EKS cluster.

       .. code-block:: shell-session

           cilium install
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
