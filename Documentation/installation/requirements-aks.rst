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
Choosing between these options depends on your specific requirements and use case. 
If you need full control over Cilium and its features, then Bring your own CNI approach might be preferred. 
On the other hand, if you prefer a managed solution with simplified installation and 
integration with Azure Virtual Network stack, then Azure CNI Powered by Cilium option might be suitable.

Another way to install Cilium on AKS is through chaining with Azure CNI :ref:`chaining_azure` and 
can be integrated with Azure Stack via :ref:`Azure IPAM<ipam_azure>`. However this integration will not work for clusters using BYOCNI. 
While it is still maintained for now, it is considered a legacy mode.