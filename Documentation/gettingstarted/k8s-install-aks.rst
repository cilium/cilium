.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_azure:
.. _k8s_install_aks:

*************************
Installation on Azure AKS
*************************

This guide covers installing Cilium into an Azure AKS environment using
:ref:`ipam_azure`.

Create an Azure Kubernetes cluster
==================================

Setup a Kubernetes cluster on Azure. You can use any method available as long
as your Kubernetes cluster has CNI enabled in the kubelet configuration. For
simplicity of this guide, we will set up a managed AKS cluster:

Prerequisites
-------------

Ensure that you have the `Azure Cloud CLI
<https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest>`_
installed and log in to Azure with:

.. code:: bash

    az login

To verify, confirm that the following command displays the set of available
Kubernetes versions.

.. code:: bash

   az aks get-versions -l westus -o table

Deploy the Cluster
------------------

.. note:: **Do NOT specify the '--network-policy' flag** when creating the
    cluster, as this will cause the Azure CNI plugin to push down unwanted
    iptables rules.

.. code:: bash

   export RESOURCE_GROUP_NAME=aks-test
   export CLUSTER_NAME=aks-test
   export LOCATION=westus

   az group create --name $RESOURCE_GROUP_NAME --location $LOCATION
   az aks create \
       --resource-group $RESOURCE_GROUP_NAME \
       --name $CLUSTER_NAME \
       --location $LOCATION \
       --node-count 2 \
       --network-plugin azure

.. note:: When setting up AKS, it is important to use the flag
          ``--network-plugin azure`` to ensure that CNI mode is enabled.

Create a service principal for cilium-operator
==============================================

In order to allow cilium-operator to interact with the Azure API, a service
principal is required. You can reuse an existing service principal if you want
but it is recommended to create a dedicated service principal for
cilium-operator:

.. code:: bash

    az ad sp create-for-rbac --name cilium-operator > azure-sp.json

The contents of ``azure-sp.json`` should look like this:

.. code:: bash

    {
      "appId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "displayName": "cilium-operator",
      "name": "http://cilium-operator",
      "password": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "tenant": "cccccccc-cccc-cccc-cccc-cccccccccccc"
    }

Extract the relevant credentials to access the Azure API:

.. code:: bash

    AZURE_SUBSCRIPTION_ID="$(az account show | jq -r .id)"
    AZURE_CLIENT_ID="$(jq -r .appId < azure-sp.json)"
    AZURE_CLIENT_SECRET="$(jq -r .password < azure-sp.json)"
    AZURE_TENANT_ID="$(jq -r .tenant < azure-sp.json)"
    AZURE_NODE_RESOURCE_GROUP="$(az aks show --resource-group $RESOURCE_GROUP_NAME --name $CLUSTER_NAME | jq -r .nodeResourceGroup)"

.. note:: ``AZURE_NODE_RESOURCE_GROUP`` must be set to the resource group of the
           node pool, *not* the resource group of the AKS cluster.

Retrieve Credentials to access cluster
======================================

.. include:: k8s-install-aks-get-credentials.rst

Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set azure.enabled=true \\
     --set azure.resourceGroup=$AZURE_NODE_RESOURCE_GROUP \\
     --set azure.subscriptionID=$AZURE_SUBSCRIPTION_ID \\
     --set azure.tenantID=$AZURE_TENANT_ID \\
     --set azure.clientID=$AZURE_CLIENT_ID \\
     --set azure.clientSecret=$AZURE_CLIENT_SECRET \\
     --set tunnel=disabled \\
     --set ipam.mode=azure \\
     --set enableIPv4Masquerade=false \\
     --set nodeinit.enabled=true

.. include:: k8s-install-restart-pods.rst
.. include:: k8s-install-validate.rst
.. include:: namespace-kube-system.rst
.. include:: hubble-enable.rst

.. _azure_limitations:

Limitations
===========

* All VMs and VM scale sets used in a cluster must belong to the same resource
  group.

.. _azure_troubleshooting:

Troubleshooting
===============
* If ``kubectl exec`` to a pod fails to connect, restarting the ``tunnelfront`` pod may help.
* Pods may fail to gain a ``.spec.hostNetwork`` status even if restarted and managed by Cilium.
* If some connectivity tests fail to reach the ready state you may need to restart the unmanaged pods again.
* Some connectivity tests may fail. This is being tracked in `Cilium GitHub issue #12113
  <https://github.com/cilium/cilium/issues/12113>`_.

  * ``hubble observe`` may report one or more nodes being unavailable and ``hubble-ui`` may fail to connect to the backends.
