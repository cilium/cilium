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

* Node pools must be properly tainted to ensure applications pods are properly
  managed by Cilium:

  * User node pools must be tainted with ``node.cilium.io/agent-not-ready=true:NoSchedule``
    to ensure application pods will only be scheduled once Cilium is ready to
    manage them.

  * System node pools must be tainted with ``CriticalAddonsOnly=true:NoSchedule``,
    preventing application pods from being scheduled on them. This is necessary
    because it is not possible to assign custom node taints such as ``node.cilium.io/agent-not-ready=true:NoSchedule``
    to system node pools, cf. `Azure/AKS#2578 <https://github.com/Azure/AKS/issues/2578>`_.
    
    * The initial node pool must be replaced with a new system node pool since
      it is not possible to assign taints to the initial node pool at this time,
      cf. `Azure/AKS#1402 <https://github.com/Azure/AKS/issues/1402>`_.

**Limitations:**

* All VMs and VM scale sets used in a cluster must belong to the same resource
  group.
