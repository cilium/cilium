.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

Self-Managed Kubernetes
=======================

The following guides are available for installation of self-managed Kubernetes
clusters. This section provides guides for installing Cilium with and without
use of a kvstore (etcd). Please refer to the section :ref:`k8s_install_etcd`
for details on when etcd is required.

.. toctree::
   :maxdepth: 1
   :glob:

   k8s-install-default
   k8s-install-etcd-operator
   k8s-install-external-etcd
   k8s-install-azure
