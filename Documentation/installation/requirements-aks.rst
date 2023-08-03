**Default Configuration:**

============================= =============== =================== ==============
Mode (``--network-plugin``)   Datapath        IPAM                Datastore
============================= =============== =================== ==============
BYOCNI (``none``)             Encapsulation   Cluster Pool        Kubernetes CRD
Legacy Azure IPAM (``azure``) Direct Routing  Azure IPAM          Kubernetes CRD
============================= =============== =================== ==============

The preferred way to run Cilium on `Azure Kubernetes Service (AKS) <https://docs.microsoft.com/en-us/azure/aks/>`_ is 
either `Bring your own CNI <https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli>`_ or 
`Azure CNI Powered by Cilium <https://learn.microsoft.com/en-us/azure/aks/azure-cni-powered-by-cilium>`_. 
There are different benefits to each option.

**Azure CNI powered by Cilium:**
- Installation and upgrades are provided by AKS.
- Cilium is configured with delegated Azure IPAM, so Pods receive IP addresses that are routable in the Azure Virtual Network Stack.

**Bring your own CNI:**
- You can customize the Cilium installation with a wider range of features.
- Azure IPAM is not available in this mode.

Another way to install Cilium on AKS is through chaining with Azure CNI :ref:`chaining_azure` and 
can be integrated with Azure Stack via :ref:`Azure IPAM<ipam_azure>`. However this integration will not work for clusters using BYOCNI. 
While it is still maintained for now, it is considered a legacy mode.