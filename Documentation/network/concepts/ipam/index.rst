.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _address_management:

****************************
IP Address Management (IPAM)
****************************

IP Address Management (IPAM) is responsible for the allocation and management
of IP addresses used by network endpoints (container and others) managed by
Cilium. Various IPAM modes are supported to meet the needs of different users:

Don't change the IPAM mode of an existing cluster. Changing the IPAM mode in
a live environment may cause persistent disruption of connectivity for existing workloads.
The safest path to change IPAM mode is to install a fresh Kubernetes cluster with the new IPAM configuration.
If you are interested in extending Cilium to support migration between IPAM modes, see :gh-issue:`27164`.

.. toctree::
   :maxdepth: 1
   :glob:

   cluster-pool
   kubernetes
   azure
   azure-delegated-ipam
   eni
   gke
   crd
   deep_dive
