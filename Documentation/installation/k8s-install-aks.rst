.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _aks_install:

*****************************************************
Installation using Azure CNI Powered by Cilium in AKS
*****************************************************

This guide walks you through the installation of Cilium on AKS (Azure Kubernetes Service) via 
the `Azure Container Network Interface (CNI) Powered by Cilium
<https://learn.microsoft.com/en-us/azure/aks/azure-cni-powered-by-cilium>`__ option.

Create the cluster
==================

Create an Azure CNI Powered by Cilium AKS cluster with ``network-plugin azure`` and 
``--network-dataplane cilium``. You can create the cluster either in ``podsubnet`` or ``overlay`` mode. 
In both modes, traffic is routed through the Azure Virtual Network Stack. The choice between these 
modes depends on the specific use case and requirements of the cluster. Refer to `the related documentation <https://learn.microsoft.com/en-us/azure/aks/azure-cni-overlay#choosing-a-network-model-to-use>`__  to know more about these two modes.

.. tabs::
  
  .. group-tab:: Overlay
  
    .. code-block:: shell-session

        az aks create -n <clusterName> -g <resourceGroupName> -l <location> \
        --network-plugin azure \
        --network-dataplane cilium \
        --network-plugin-mode overlay \
        --pod-cidr 192.168.0.0/16

    See also `the detailed instructions from scratch 
    <https://learn.microsoft.com/en-us/azure/aks/azure-cni-powered-by-cilium#option-1-assign-ip-addresses-from-an-overlay-network>`__.

  .. group-tab:: Podsubnet
    
    .. code-block:: shell-session

        az aks create -n <clusterName> -g <resourceGroupName> -l <location> \
        --network-plugin azure \
        --network-dataplane cilium \
        --vnet-subnet-id /subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/virtualNetworks/<vnetName>/subnets/nodesubnet \
        --pod-subnet-id /subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/virtualNetworks/<vnetName>/subnets/podsubnet 

    See also `the detailed instructions from scratch
    <https://learn.microsoft.com/en-us/azure/aks/azure-cni-powered-by-cilium#option-2-assign-ip-addresses-from-a-virtual-network>`_. 
    
.. include:: k8s-install-validate.rst

Delegated Azure IPAM
====================

Delegated Azure IPAM (IP Address Manager) manages the IP allocation for pods created in Azure CNI Powered by Cilium clusters.
It assigns IPs that are routable in Azure Virtual Network stack. To know more about the Delegated Azure IPAM, 
see :ref:`azure_delegated_ipam`.
