To install Cilium on `Azure Kubernetes Service (AKS) <https://docs.microsoft.com/en-us/azure/aks/>`_,
perform the following steps:

**Default Configuration:**

=============== =================== ==============
Datapath        IPAM                Datastore
=============== =================== ==============
Direct Routing  Azure IPAM          Kubernetes CRD
=============== =================== ==============

.. tip::

   If you want to chain Cilium on top of the Azure CNI, refer to the guide
   :ref:`chaining_azure`.

**Requirements:**

* The AKS cluster must be created with ``--network-plugin azure`` for
  compatibility with Cilium. The Azure network plugin will be replaced with
  Cilium by the installer.

* Node pools must also be created with the taint ``node.cilium.io/agent-not-ready=true:NoSchedule``
  using ``--node-taints`` option.

**Limitations:**

* All VMs and VM scale sets used in a cluster must belong to the same resource
  group.
