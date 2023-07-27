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
distribution you are using. All state is stored using Kubernetes custom resource definitions (CRDs).

This is the best installation method for most use cases.  For large
environments (> 500 nodes) or if you want to run specific datapath modes, refer
to the :ref:`k8s_install_advanced` guide.

Should you encounter any issues during the installation, please refer to the
:ref:`troubleshooting_k8s` section and/or seek help on `Cilium Slack`_.

.. _create_cluster:

Create the Cluster
===================

If you don't have a Kubernetes Cluster yet, you can use the instructions below
to create a Kubernetes cluster locally or using a managed Kubernetes service:

.. tabs::

    .. group-tab:: GKE

       The following commands create a Kubernetes cluster using `Google
       Kubernetes Engine <https://cloud.google.com/kubernetes-engine>`_.  See
       `Installing Google Cloud SDK <https://cloud.google.com/sdk/install>`_
       for instructions on how to install ``gcloud`` and prepare your
       account.

       .. code-block:: bash

           export NAME="$(whoami)-$RANDOM"
           # Create the node pool with the following taint to guarantee that
           # Pods are only scheduled/executed in the node when Cilium is ready.
           # Alternatively, see the note below.
           gcloud container clusters create "${NAME}" \
            --node-taints node.cilium.io/agent-not-ready=true:NoExecute \
            --zone us-west2-a
           gcloud container clusters get-credentials "${NAME}" --zone us-west2-a

       .. note::

          Please make sure to read and understand the documentation page on :ref:`taint effects and unmanaged pods<taint_effects>`.

    .. group-tab:: AKS (BYOCNI)

       .. note::

          BYOCNI is the preferred way to run Cilium on AKS, however integration
          with the Azure stack via the :ref:`Azure IPAM<ipam_azure>` is not
          available. If you require Azure IPAM, refer to the AKS (Azure IPAM)
          installation.

       The following commands create a Kubernetes cluster using `Azure
       Kubernetes Service <https://docs.microsoft.com/en-us/azure/aks/>`_ with
       no CNI plugin pre-installed (BYOCNI). See `Azure Cloud CLI
       <https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest>`_
       for instructions on how to install ``az`` and prepare your account, and
       the `Bring your own CNI documentation
       <https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli>`_
       for more details about BYOCNI prerequisites / implications.

       .. note::

          BYOCNI requires the ``aks-preview`` CLI extension with version >=
          0.5.55, which itself requires an ``az`` CLI version >= 2.32.0 .

       .. code-block:: bash

           export NAME="$(whoami)-$RANDOM"
           export AZURE_RESOURCE_GROUP="${NAME}-group"
           az group create --name "${AZURE_RESOURCE_GROUP}" -l westus2

           # Create AKS cluster
           az aks create \
             --resource-group "${AZURE_RESOURCE_GROUP}" \
             --name "${NAME}" \
             --network-plugin none

           # Get the credentials to access the cluster with kubectl
           az aks get-credentials --resource-group "${AZURE_RESOURCE_GROUP}" --name "${NAME}"

    .. group-tab:: AKS (Azure IPAM)

       .. note::

          :ref:`Azure IPAM<ipam_azure>` offers integration with the Azure stack
          but is not the preferred way to run Cilium on AKS. If you do not
          require Azure IPAM, we recommend you to switch to the AKS (BYOCNI)
          installation.

       The following commands create a Kubernetes cluster using `Azure
       Kubernetes Service <https://docs.microsoft.com/en-us/azure/aks/>`_. See
       `Azure Cloud CLI
       <https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest>`_
       for instructions on how to install ``az`` and prepare your account.

       .. code-block:: bash

           export NAME="$(whoami)-$RANDOM"
           export AZURE_RESOURCE_GROUP="${NAME}-group"
           az group create --name "${AZURE_RESOURCE_GROUP}" -l westus2

           # Create AKS cluster
           az aks create \
             --resource-group "${AZURE_RESOURCE_GROUP}" \
             --name "${NAME}" \
             --network-plugin azure \
             --node-count 2

           # Get the credentials to access the cluster with kubectl
           az aks get-credentials --resource-group "${AZURE_RESOURCE_GROUP}" --name "${NAME}"

       .. attention::

           Do NOT specify the ``--network-policy`` flag when creating the
           cluster, as this will cause the Azure CNI plugin to install unwanted
           iptables rules.

    .. group-tab:: EKS

       The following commands create a Kubernetes cluster with ``eksctl``
       using `Amazon Elastic Kubernetes Service
       <https://aws.amazon.com/eks/>`_.  See `eksctl Installation
       <https://github.com/weaveworks/eksctl>`_ for instructions on how to
       install ``eksctl`` and prepare your account.

       .. code-block:: none

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
             # not scheduled/executed until Cilium is deployed.
             # Alternatively, see the note below.
             taints:
              - key: "node.cilium.io/agent-not-ready"
                value: "true"
                effect: "NoExecute"
           EOF
           eksctl create cluster -f ./eks-config.yaml

       .. note::

          Please make sure to read and understand the documentation page on :ref:`taint effects and unmanaged pods<taint_effects>`.

    .. group-tab:: kind

       Install ``kind`` >= v0.7.0 per kind documentation:
       `Installation and Usage <https://kind.sigs.k8s.io/#installation-and-usage>`_

       .. parsed-literal::

          curl -LO \ |SCM_WEB|\/Documentation/gettingstarted/kind-config.yaml
          kind create cluster --config=kind-config.yaml

    .. group-tab:: minikube

       Install minikube >= v1.12 as per minikube documentation:
       `Install Minikube <https://kubernetes.io/docs/tasks/tools/install-minikube/>`_.
       The following command will bring up a single node minikube cluster prepared for installing cilium.

       .. code-block:: shell-session

          minikube start --network-plugin=cni --cni=false

       .. note::

          From minikube v1.12.1+, cilium networking plugin can be enabled directly with
          ``--cni=cilium`` parameter in ``minikube start`` command. However, this may not
          install the latest version of cilium.

    .. group-tab:: Rancher Desktop

       Install Rancher Desktop >= v1.1.0 as per Rancher Desktop documentation:
       `Install Rancher Desktop <https://docs.rancherdesktop.io/getting-started/installation>`_.

       Next you need to configure Rancher Desktop so to disable the builtin CNI so you can install Cilium.

       .. include:: rancher-desktop-configure.rst


Install the Cilium CLI
======================

.. include:: cli-download.rst

.. admonition:: Video
  :class: attention

  To learn more about the Cilium CLI, check out `eCHO episode 8: Exploring the Cilium CLI <https://www.youtube.com/watch?v=ndjmaM1i0WQ&t=1136s>`__.


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

       .. parsed-literal::

          cilium install |CHART_VERSION|

    .. group-tab:: GKE

       .. include:: requirements-gke.rst

       **Install Cilium:**

       Install Cilium into the GKE cluster:

       .. parsed-literal::

           cilium install |CHART_VERSION|

    .. group-tab:: AKS (BYOCNI)

       .. include:: requirements-aks-byocni.rst

       **Install Cilium:**

       Install Cilium into the AKS cluster:

       .. parsed-literal::

           cilium install |CHART_VERSION| --set azure.resourceGroup="${AZURE_RESOURCE_GROUP}"

    .. group-tab:: AKS (Azure IPAM)

       .. include:: requirements-aks-azure-ipam.rst

       **Install Cilium:**

       Install Cilium into the AKS cluster:

       .. code-block:: shell-session

           cilium install |CHART_VERSION| --set azure.resourceGroup="${AZURE_RESOURCE_GROUP}"

    .. group-tab:: EKS

       .. include:: requirements-eks.rst

       **Install Cilium:**

       Install Cilium into the EKS cluster.

       .. parsed-literal::

           cilium install |CHART_VERSION|
           cilium status --wait

       .. note::

           If you have to uninstall Cilium and later install it again, that could cause
           connectivity issues due to ``aws-node`` DaemonSet flushing Linux routing tables.
           The issues can be fixed by restarting all pods, alternatively to avoid such issues
           you can delete ``aws-node`` DaemonSet prior to installing Cilium.

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

       .. parsed-literal::

           cilium install |CHART_VERSION|

    .. group-tab:: k3s

       .. include:: requirements-k3s.rst

       **Install Cilium:**

       Install Cilium into your newly created Kubernetes cluster:

       .. parsed-literal::

           cilium install |CHART_VERSION|


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
