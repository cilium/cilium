.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _azure_delegated_ipam:

####################
Azure Delegated IPAM
####################

The Azure CNI powered by Cilium cluster utilizes a delegated IPAM (IP Address Manager) approach to allocate 
IP addresses for pods that are created using the Cilium CNI. This delegated IPAM component manages IP allocation 
within individual nodes of the cluster. It collaborates closely with the AKS (Azure Kubernetes Service) control plane 
components to seamlessly integrate with the broader Azure Virtual Network stack. 

Cilium CNI is specifically configured with delegated IPAM details in its configuration, allowing it to interact 
with the delegated Azure IPAM. This configuration ensures that the Cilium CNI triggers the delegated IPAM during 
both pod addition and deletion operations. Upon receiving Add request, the delegated IPAM allocates an available 
IP address from its cache. Similarly on Delete request, the delegated IPAM marks IP as available. 
