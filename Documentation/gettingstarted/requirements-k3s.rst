To install Cilium on `k3s <https://rancher.com/docs/k3s/latest/en/quick-start/>`_,
perform the following steps:

**Default Configuration:**

=============== =============== ==============
Datapath        IPAM            Datastore
=============== =============== ==============
Encapsulation   Cluster Pool    Kubernetes CRD
=============== =============== ==============

**Requirements:**

* Install your k3s cluster as you would normally would but pass in
  ``--flannel-backend=none`` so you can install Cilium on top:

.. code-block:: shell-session

   curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--flannel-backend=none' sh -
