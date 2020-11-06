.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_aks:

*************************
Installation on Azure AKS
*************************

This guide covers installing Cilium into an Azure AKS environment. This guide
will work when setting up AKS in both `Basic <https://docs.microsoft.com/en-us/azure/aks/concepts-network#kubenet-basic-networking>`_ and `Advanced 
<https://docs.microsoft.com/en-us/azure/aks/concepts-network#azure-cni-advanced-networking>`_ networking mode.

This is achieved using Cilium in CNI chaining mode, with the Azure CNI plugin
as the base CNI plugin and Cilium chaining on top to provide L3-L7
observability, network policy enforcement, Kubernetes services
implementation, as well as other advanced features like transparent encryption
and clustermesh.

Prerequisites
=============

Ensure that you have the `Azure Cloud CLI
<https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest>`_
installed and log in to Azure with:

.. code:: bash

    az login

To verify, confirm that the following command displays the set of available
Kubernetes versions.

.. code:: bash

   az aks get-versions -l westus -o table

Create an AKS Cluster
=====================

You can use any method to create and deploy an AKS cluster with the exception
of specifying the Network Policy option. Doing so will still work but will
result in unwanted iptables rules being installed on all of your nodes.

If you want to us the CLI to create a dedicated set of Azure resources
(resource groups, networks, etc.) specifically for this tutorial, the following
commands (borrowed from the AKS documentation) run as a script or manually all
in the same terminal are sufficient.

It can take 10+ minutes for the final command to be complete indicating that
the cluster is ready.

.. include:: k8s-install-aks-create-cluster.rst

Configure kubectl to Point to Newly Created Cluster
===================================================

Run the following commands to configure kubectl to connect to this
AKS cluster:

.. include:: k8s-install-aks-get-credentials.rst

To verify, you should see AKS in the name of the nodes when you run:

.. code-block:: shell-session

    $ kubectl get nodes
    NAME                                STATUS   ROLES   AGE   VERSION
    aks-nodepool1-22314427-vmss000000   Ready    agent   91s   v1.17.11
    aks-nodepool1-22314427-vmss000001   Ready    agent   91s   v1.17.11

.. include:: k8s-install-azure-cni-steps.rst

.. include:: k8s-install-azure-cni-validate.rst
.. include:: namespace-cilium.rst
.. include:: hubble-enable.rst

Delete the AKS Cluster
======================

Finally, delete the test cluster by running:

.. code:: bash

    az aks delete \
        --resource-group $RESOURCE_GROUP_NAME \
        --name $CLUSTER_NAME