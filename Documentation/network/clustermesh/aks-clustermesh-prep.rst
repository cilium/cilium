.. _gs_clustermesh_aks_prep:

**********************************
AKS-to-AKS Clustermesh Preparation
**********************************

This is a step-by-step guide on how to install and prepare 
AKS (Azure Kubernetes Service) clusters in BYOCNI mode to meet the requirements 
for the clustermesh feature.

In this guide we will install two AKS clusters in BYOCNI (Bring Your Own CNI) 
mode and connect them together via clustermesh. This guide is not 
applicable for cross-cloud clustermesh since this guide doesn't expose the node
IPs outside of the Azure cloud.

.. note::

        BYOCNI requires the ``aks-preview`` CLI extension with version >=
        0.5.55, which itself requires an ``az`` CLI version >= 2.32.0.

Install cluster one
###################

1.  Create a resource group for the cluster (or set the environment variables
    to an existing resource group).

    .. code-block:: bash

        export NAME="$(whoami)-$RANDOM"
        export AZURE_RESOURCE_GROUP="${NAME}-group"

        #  westus2 can be changed to any available location (`az account list-locations`)
        az group create --name "${AZURE_RESOURCE_GROUP}" -l westus2

2.  Now that we have a resource group we can create a VNet (virtual network). 
    Creating a custom VNet is required so we can specify a unique Node, Pod, and 
    Service CIDRs to make sure we don't overlap with other clusters.

    .. note::
        In this case we use the ``192.168.10.0/24`` range, but this can be exchanged
        for any range except for ``169.254.0.0/16``, ``172.30.0.0/16``, 
        ``172.31.0.0/16``, or ``192.0.2.0/24`` which are 
        `reserved by Azure <https://docs.microsoft.com/en-us/azure/aks/configure-azure-cni#prerequisites>`__.

    .. code-block:: bash

        az network vnet create \
            --resource-group "${AZURE_RESOURCE_GROUP}" \
            --name "${NAME}-cluster-net" \
            --address-prefixes 192.168.10.0/24 \
            --subnet-name "${NAME}-node-subnet" \
            --subnet-prefix 192.168.10.0/24

        # Store the ID of the created subnet
        export NODE_SUBNET_ID=$(az network vnet subnet show \
            --resource-group "${AZURE_RESOURCE_GROUP}" \
            --vnet-name "${NAME}-cluster-net" \
            --name "${NAME}-node-subnet" \
            --query id \
            -o tsv)

3.  We now have a virtual network and a subnet with the same CIDR. We can 
    create an AKS cluster without CNI and request to use our custom VNet and subnet.

    During creation we also request to use ``"10.10.0.0/16`` as the pod CIDR and
    ``"10.11.0.0/16`` as the services CIDR. These can be changed to any range
    except for Azure reserved ranges and ranges used by other clusters we intend to
    add to the clustermesh.

    .. code-block:: bash

        az aks create \
            --resource-group "${AZURE_RESOURCE_GROUP}" \
            --name "${NAME}" \
            --network-plugin none \
            --pod-cidr "10.10.0.0/16" \
            --service-cidr "10.11.0.0/16" \
            --dns-service-ip "10.11.0.10" \
            --vnet-subnet-id "${NODE_SUBNET_ID}"

        # Get kubectl credentials, the command will merge the new credentials
        # with the existing ~/.kube/config
        az aks get-credentials \
            --resource-group "${AZURE_RESOURCE_GROUP}" \
            --name "${NAME}"

4.  Install Cilium, it is important to give
    the cluster a unique cluster ID and to tell Cilium to use our custom pod CIDR.

    .. code-block:: bash

        cilium install \
            --azure-resource-group "${AZURE_RESOURCE_GROUP}" \
            --cluster-id 1 \
            --config "cluster-pool-ipv4-cidr=10.10.0.0/16"

5.  Check the status of Cilium.

    .. code-block:: bash

        cilium status   

6.  Before we continue with cluster two, store the name of the current cluster.

    .. code-block:: bash

        export CLUSTER1=${NAME}


Install cluster two
###################

Installing the second cluster uses the same commands but with slightly different
arguments.

1.  Create a new resource group.

    .. code-block:: bash

        export NAME="$(whoami)-$RANDOM"
        export AZURE_RESOURCE_GROUP="${NAME}-group"

        # eastus2 can be changed to any available location (`az account list-locations`)
        az group create --name "${AZURE_RESOURCE_GROUP}" -l eastus2

2.  Create a VNet in this resource group. Make sure to use a non-overlapping prefix.

    .. note::
        In this case we use the ``192.168.20.0/24`` range, but this can be exchanged
        for any range except for ``169.254.0.0/16``, ``172.30.0.0/16``, 
        ``172.31.0.0/16``, or ``192.0.2.0/24`` which are 
        `reserved by Azure <https://docs.microsoft.com/en-us/azure/aks/configure-azure-cni#prerequisites>`__.

    .. code-block:: bash

        az network vnet create \
            --resource-group "${AZURE_RESOURCE_GROUP}" \
            --name "${NAME}-cluster-net" \
            --address-prefixes 192.168.20.0/24 \
            --subnet-name "${NAME}-node-subnet" \
            --subnet-prefix 192.168.20.0/24

        # Store the ID of the created subnet
        export NODE_SUBNET_ID=$(az network vnet subnet show \
            --resource-group "${AZURE_RESOURCE_GROUP}" \
            --vnet-name "${NAME}-cluster-net" \
            --name "${NAME}-node-subnet" \
            --query id \
            -o tsv)

3.  Create an AKS cluster without CNI and request to use our custom VNet and 
    subnet.

    During creation we also request to use ``"10.20.0.0/16`` as the pod CIDR and
    ``"10.21.0.0/16`` as the services CIDR. These can be changed to any range
    except for Azure reserved ranges and ranges used by other clusters we intend to
    add to the clustermesh.

    .. code-block:: bash

        az aks create \
            --resource-group "${AZURE_RESOURCE_GROUP}" \
            --name "${NAME}" \
            --network-plugin none \
            --pod-cidr "10.20.0.0/16" \
            --service-cidr "10.21.0.0/16" \
            --dns-service-ip "10.21.0.10" \
            --vnet-subnet-id "${NODE_SUBNET_ID}"

        # Get kubectl credentials and add them to ~/.kube/config
        az aks get-credentials \
            --resource-group "${AZURE_RESOURCE_GROUP}" \
            --name "${NAME}"

4.  Install Cilium, it is important to give
    the cluster a unique cluster ID and to tell Cilium to use our custom pod CIDR.

    .. code-block:: bash
        
        cilium install \
            --azure-resource-group "${AZURE_RESOURCE_GROUP}" \
            --cluster-id 2 \
            --config "cluster-pool-ipv4-cidr=10.20.0.0/16"

5.  Check the status of Cilium.

    .. code-block:: bash

        cilium status

6.  Before we continue with peering and clustermesh, store the current cluster 
    name.

    .. code-block:: bash

        export CLUSTER2=${NAME}

Peering virtual networks
########################

Virtual networks can't connect to each other by default. We can enable cross
VNet communication by creating bi-directional "peering".

We will start by creating a peering from cluster one to cluster two using the
following commands.

.. code-block:: bash

    export VNET_ID=$(az network vnet show \
        --resource-group "${CLUSTER2}-group" \
        --name "${CLUSTER2}-cluster-net" \
        --query id -o tsv)

    az network vnet peering create \
        -g "${CLUSTER1}-group" \
        --name "peering-${CLUSTER1}-to-${CLUSTER2}" \
        --vnet-name "${CLUSTER1}-cluster-net" \
        --remote-vnet "${VNET_ID}" \
        --allow-vnet-access

This allows outbound traffic from cluster one to cluster two. To allow 
bi-directional traffic, we need to add peering to the other direction as well.

.. code-block:: bash

    export VNET_ID=$(az network vnet show \
        --resource-group "${CLUSTER1}-group" \
        --name "${CLUSTER1}-cluster-net" \
        --query id -o tsv)

    az network vnet peering create \
        -g "${CLUSTER2}-group" \
        --name "peering-${CLUSTER2}-to-${CLUSTER1}" \
        --vnet-name "${CLUSTER2}-cluster-net" \
        --remote-vnet "${VNET_ID}" \
        --allow-vnet-access

Node-to-node traffic between clusters is now possible. All requirements for 
clustermesh are met. Enabling clustermesh is explained in :ref:`gs_clustermesh`.
