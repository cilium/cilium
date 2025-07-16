.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gsg_ipam:

**********************
Configuring IPAM Modes
**********************

Cilium supports multiple IP Address Management (IPAM) modes to meet the needs
of different environments and cloud providers.

The following sections provide documentation for each supported IPAM mode:

.. toctree::
   :maxdepth: 1
   :glob:

   ipam-crd
   ipam-cluster-pool
   ipam-multi-pool

   ../concepts/ipam/kubernetes
   ../concepts/ipam/azure
   ../concepts/ipam/azure-delegated-ipam
   ../concepts/ipam/eni
