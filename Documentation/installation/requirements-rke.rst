To install Cilium on `Rancher Kubernetes Engine (RKE) <https://rancher.com/docs/rke/latest/en/>`_,
perform the following steps:

.. note::

   If you are using RKE2, Cilium has been directly integrated. Please see
   `Using Cilium <https://docs.rke2.io/install/network_options#install-a-cni-plugin>`_
   in the RKE2 documentation. You can use either method.

**Default Configuration:**

=============== =============== ==============
Datapath        IPAM            Datastore
=============== =============== ==============
Encapsulation   Cluster Pool    Kubernetes CRD
=============== =============== ==============

**Requirements:**

* Follow the `RKE Installation Guide <https://rancher.com/docs/rke/latest/en/installation/>`_
  with the below change:

  From:

  .. code-block:: yaml

     network:
       options:
         flannel_backend_type: "vxlan"
       plugin: "canal"

  To:

  .. code-block:: yaml

     network:
       plugin: none
