**Default Configuration:**

============================= =============== =================== ==============
Mode (``--network-plugin``)   Datapath        IPAM                Datastore
============================= =============== =================== ==============
BYOCNI (``none``)             Encapsulation   Cluster Pool        Kubernetes CRD
Legacy Azure IPAM (``azure``) Direct Routing  Azure IPAM          Kubernetes CRD
============================= =============== =================== ==============

Using `Bring your own CNI <https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli>`_
is the preferred way to run Cilium on `Azure Kubernetes Service (AKS) <https://docs.microsoft.com/en-us/azure/aks/>`_,
however integration with the Azure stack via the :ref:`Azure IPAM<ipam_azure>`
is not available and will only work with clusters not using BYOCNI. While still
maintained for now, this mode is considered legacy.
