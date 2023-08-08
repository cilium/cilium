.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _aks_install:

*****************************************************
Installation using Azure CNI Powered by Cilium in AKS
*****************************************************
This guide walks you through installation of Cilium on AKS (Azure Kubernetes Service) via 
Azure Container Network Interface (CNI) Powered by Cilium option
<https://learn.microsoft.com/en-us/azure/aks/azure-cni-powered-by-cilium>`_.

Create the cluster
==================
Azure CNI Powered by Cilium AKS cluster must be created with ``network-plugin azure`` and 
``--network-dataplane cilium``. Cluster can be created either in the ``podsubnet`` or ``overlay`` mode. 
In both modes, traffic will be routed through the Azure Virtual Network Stack. The choice between these 
modes are dependent upon specific use case and requirements of the cluster. Follow this page to know more 
about these two modes `<https://learn.microsoft.com/en-us/azure/aks/azure-cni-overlay#choosing-a-network-model-to-use>`_.


.. tabs::
  .. group-tab:: Overlay

    .. code-block:: shell-session

        az aks create -n <clusterName> -g <resourceGroupName> -l <location> \
        --network-plugin azure \
        --network-dataplane cilium \
        --network-plugin-mode overlay \
        --pod-cidr 192.168.0.0/16
 
  .. group-tab:: Podsubnet
    
    .. code-block:: shell-session

        az aks create -n <clusterName> -g <resourceGroupName> -l <location> \
        --network-plugin azure \
        --network-dataplane cilium \
        --vnet-subnet-id /subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/virtualNetworks/<vnetName>/subnets/nodesubnet \
        --pod-subnet-id /subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/virtualNetworks/<vnetName>/subnets/podsubnet 

.. include:: k8s-install-validate.rst

Delegated Azure IPAM
====================
Delegated Azure IPAM (IP Address Manager) manages the IP allocation for pods created in Azure CNI Powered by Cilium cluster. 
It assigns IPs that are routable in Azure Virtual Network stack. To know more about Delegated Azure Ipam, 
follow this page :ref:`Delegatd Ipam<azure_delegated_ipam>`
