To install Cilium on `k3s <https://rancher.com/docs/k3s/latest/en/quick-start/>`_,
perform the following steps:

**Default Configuration:**

=============== =============== ==============
Datapath        IPAM            Datastore
=============== =============== ==============
Encapsulation   Cluster Pool    Kubernetes CRD
=============== =============== ==============

**Requirements:**

* Install your k3s cluster as you normally would but making sure to disable
  support for the default CNI plugin and the built-in network policy enforcer so
  you can install Cilium on top:

.. code-block:: shell-session

    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--flannel-backend=none --disable-network-policy' sh -
