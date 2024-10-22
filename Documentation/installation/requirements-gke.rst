To install Cilium on `Google Kubernetes Engine (GKE) <https://cloud.google.com/kubernetes-engine>`_,
perform the following steps:

**Default Configuration:**

=============== =================== ===============
Datapath        IPAM                Datastore
=============== =================== ===============
Direct Routing  Kubernetes PodCIDR  Kubernetes CRD
=============== =================== ===============

**Requirements:**

* The cluster should be created with the taint ``node.cilium.io/agent-not-ready=true:NoExecute``
  using ``--node-taints`` option. However, there are other options. Please make
  sure to read and understand the documentation page on :ref:`taint effects and unmanaged pods<taint_effects>`.
