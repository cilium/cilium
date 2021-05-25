To install Cilium on `Google Kubernetes Engine (GKE) <https://cloud.google.com/kubernetes-engine>`_,
perform the following steps:

**Default Configuration:**

=============== =================== ===============
Datapath        IPAM                Datastore
=============== =================== ===============
Direct Routing  Kubernetes PodCIDR  Kubernetes CRD
=============== =================== ===============

**Requirements:**

* No special requirements. The Cilium installer will automatically
  reconfigure your GKE cluster to use CNI mode.
