**Configuration:**

============= ============ ==============
Datapath      IPAM         Datastore
============= ============ ==============
Encapsulation Cluster Pool Kubernetes CRD
============= ============ ============== 

**Requirements:**

.. note::

    On AKS, Cilium can be installed either manually by administrators via Bring your own CNI or 
    automatically by AKS via Azure CNI Powered by Cilium. Bring your own CNI offers more flexibility 
    and customization as administrators have full control over the installation, but it does not 
    integrate natively with the Azure network stack and administrators need to handle Cilium upgrades. 
    Azure CNI Powered by Cilium integrates natively with the Azure network stack and upgrades are 
    handled by AKS, but it does not offer as much flexibility and customization as it is controlled by AKS. 
    The following instructions assume Bring your own CNI. For Azure CNI Powered by 
    Cilium, see the external installer guide :ref:`aks_install` for dedicated instructions.

* The AKS cluster must be created with ``--network-plugin none``. See the
  `Bring your own CNI <https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli>`_
  documentation for more details about BYOCNI prerequisites / implications.

* Make sure that you set a cluster pool IPAM pod CIDR that does not overlap with the default service
  CIDR of AKS. For example, you can use ``--helm-set ipam.operator.clusterPoolIPv4PodCIDRList=192.168.0.0/16``.
