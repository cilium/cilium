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


============================ ======================= ========================= ================== ============ =============== ================= =============
Feature                      Kubernetes Host Scope   Cluster Scope (default)   Cluster Scope v2   CRD-backed   AWS ENI         Azure IPAM         GKE
============================ ======================= ========================= ================== ============ =============== ================= =============
Tunnel routing               ✅                      ✅                        ❌                 ❌           ❌              ❌                ❌
Direct routing               ✅                      ✅                        ✅                 ✅           ✅              ✅                ✅
CIDR Configuration           Kubernetes              Cilium                    Cilium             External     External (AWS)  External (Azure)  External (GCP)
Multiple CIDRs per cluster   ❌                      ✅                        ✅                 N/A          N/A             N/A               N/A
Multiple CIDRs per node      ❌                      ❌                        ✅                 N/A          N/A             N/A               N/A
Dynamic CIDR/IP allocation   ❌                      ❌                        ✅                 ✅           ✅              ✅                ❌
============================ ======================= ========================= ================== ============ =============== ================= =============


.. toctree::
   :maxdepth: 1
   :glob:

   cluster-pool
   kubernetes
   azure
   eni
   gke
   crd
   deep_dive
