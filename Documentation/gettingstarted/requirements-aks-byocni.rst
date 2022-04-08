To install Cilium on `Azure Kubernetes Service (AKS) <https://docs.microsoft.com/en-us/azure/aks/>`_
in `Bring your own CNI <https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli>`_
mode, perform the following steps:

**Default Configuration:**

=============== =================== ==============
Datapath        IPAM                Datastore
=============== =================== ==============
Encapsulation   Cluster Pool        Kubernetes CRD
=============== =================== ==============

.. note::

   BYOCNI is the preferred way to run Cilium on AKS, however integration with
   the Azure stack via the :ref:`Azure IPAM<ipam_azure>` is not available. If
   you require Azure IPAM, refer to the AKS (Azure IPAM) installation.

**Requirements:**

* The AKS cluster must be created with ``--network-plugin none`` (BYOCNI). See
  the `Bring your own CNI documentation <https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli>`_
  for more details about BYOCNI prerequisites / implications.
