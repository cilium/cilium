To install Cilium on `Google Kubernetes Engine (GKE) <https://cloud.google.com/kubernetes-engine>`_,
perform the following steps:

**Default Configuration:**

=============== =================== ===============
Datapath        IPAM                Datastore
=============== =================== ===============
Direct Routing  Kubernetes PodCIDR  Kubernetes CRD
=============== =================== ===============

**Requirements:**

* The cluster must  be created with the taint ``node.cilium.io/agent-not-ready=true:NoSchedule``
  using ``--node-taints`` option.
