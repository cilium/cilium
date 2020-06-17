.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_azure:

********************************************
Installation on Microsoft Azure Cloud (beta)
********************************************

This guide explains how to configure Cilium in Azure Cloud to use :ref:`ipam_azure`.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

Create an Azure Kubernetes cluster
==================================

Setup a Kubernetes cluster on Azure. You can use any method available as long
as your Kubernetes cluster has CNI enabled in the kubelet configuration. For
simplicity of this guide, we will set up a managed AKS cluster:

.. include:: k8s-install-aks-create-cluster.rst

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
     --set global.azure.enabled=true \\
     --set global.azure.resourceGroup=$AZURE_NODE_RESOURCE_GROUP \\
     --set global.azure.subscriptionID=$AZURE_SUBSCRIPTION_ID \\
     --set global.azure.tenantID=$AZURE_TENANT_ID \\
     --set global.azure.clientID=$AZURE_CLIENT_ID \\
     --set global.azure.clientSecret=$AZURE_CLIENT_SECRET \\
     --set global.tunnel=disabled \\
     --set config.ipam=azure \\
     --set global.masquerade=false \\
     --set global.nodeinit.enabled=true

.. include:: k8s-install-validate.rst
.. include:: namespace-kube-system.rst
.. include:: hubble-enable.rst

.. _azure_limitations:

Limitations
===========

* All VMs and VM scale sets used in a cluster must belong to the same resource
  group.
