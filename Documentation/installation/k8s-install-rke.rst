.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _rke_install:

********************************************
Installation using Rancher Kubernetes Engine
********************************************

This guide walks you through installation of Cilium on **standalone**
`Rancher Kubernetes Engine (RKE) <https://www.rancher.com/products/secure-kubernetes-distribution>`__
clusters, SUSE's CNCF-certified Kubernetes distribution with built-in security
and compliance capabilities.
RKE solves the common frustration of installation complexity with Kubernetes by
removing most host dependencies and presenting a stable path for deployment,
upgrades, and rollbacks.

If you're using the Rancher Management Console/UI to install your RKE clusters, head
over to the :ref:`Installation using Rancher <rancher_managed_rke_clusters>` guide.

.. _rke1_cni_none:

Install a Cluster Using RKE1
=============================

The first step is to install a cluster based on the `RKE1 Kubernetes installation guide <https://rke.docs.rancher.com/installation>`__.
When creating the cluster, make sure to `change the default network plugin <https://rancher.com/docs/rke/latest/en/config-options/add-ons/network-plugins/custom-network-plugin-example/>`__
in the generated ``config.yaml`` file.

Change:

.. code-block:: yaml

  network:
    options:
      flannel_backend_type: "vxlan"
    plugin: "canal"

To:

.. code-block:: yaml

  network:
    plugin: none


Install a Cluster Using RKE2
=============================

The first step is to install a cluster based on the `RKE2 Kubernetes installation guide <https://docs.rke2.io/install/quickstart>`__.
You can either use the `RKE2-integrated Cilium version <https://docs.rke2.io/install/network_options#install-a-cni-plugin>`__
or you can configure the RKE2 cluster with ``cni: none`` (see `doc <https://docs.rke2.io/reference/server_config>`__),
and install Cilium with Helm. You can use either method while the
directly integrated one is recommended for most users.

Cilium power-users might want to use the ``cni: none`` method as Rancher is using
a custom ``rke2-cilium`` `Helm chart <https://github.com/rancher/rke2-charts/tree/main-source/packages/rke2-cilium>`__
with independent release cycles for its integrated Cilium version. By instead using the
out-of-band Cilium installation (based on the official
`Cilium Helm chart <https://github.com/cilium/charts>`__),
power-users gain more flexibility from a Cilium perspective.

Deploy Cilium
=============

.. tabs::

    .. group-tab:: Helm v3

        Install Cilium via ``helm install``:

        .. parsed-literal::

           helm repo add cilium https://helm.cilium.io
           helm repo update
           helm install cilium |CHART_RELEASE| \\
              --namespace $CILIUM_NAMESPACE

    .. group-tab:: Cilium CLI

        .. include:: cli-download.rst

        Install Cilium by running:

        .. parsed-literal::

            cilium install |CHART_VERSION|

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst
