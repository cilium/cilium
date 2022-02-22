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
<https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest>`_ installed.

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

Create a Service principal for cilium-operator
==============================================

In order to allow cilium-operator to interact with the Azure API, a Service
Principal with ``Contributor`` privileges over the AKS cluster is required (see
:ref:`Azure IPAM required privileges <ipam_azure_required_privileges>` for more
details). It is recommended to create a dedicated Service Principal for each
Cilium installation with minimal privileges over the AKS node resource group:

.. code-block:: shell-session

    AZURE_SUBSCRIPTION_ID=$(az account show --query "id" --output tsv)
    AZURE_NODE_RESOURCE_GROUP=$(az aks show --resource-group ${RESOURCE_GROUP} --name ${CLUSTER_NAME} --query "nodeResourceGroup" --output tsv)
    AZURE_SERVICE_PRINCIPAL=$(az ad sp create-for-rbac --scopes /subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${AZURE_NODE_RESOURCE_GROUP} --role Contributor --output json --only-show-errors)
    AZURE_TENANT_ID=$(echo ${AZURE_SERVICE_PRINCIPAL} | jq -r '.tenant')
    AZURE_CLIENT_ID=$(echo ${AZURE_SERVICE_PRINCIPAL} | jq -r '.appId')
    AZURE_CLIENT_SECRET=$(echo ${AZURE_SERVICE_PRINCIPAL} | jq -r '.password')

.. note::

    The ``AZURE_NODE_RESOURCE_GROUP`` node resource group is *not* the
    resource group of the AKS cluster. A single resource group may hold
    multiple AKS clusters, but each AKS cluster regroups all resources in
    an automatically managed secondary resource group. See `Why are two
    resource groups created with AKS? <https://docs.microsoft.com/en-us/azure/aks/faq#why-are-two-resource-groups-created-with-aks>`__
    for more details.

    This ensures the Service Principal only has privileges over the AKS
    cluster itself and not any other resources within the resource group.

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
     --set masquerade=false \\
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
