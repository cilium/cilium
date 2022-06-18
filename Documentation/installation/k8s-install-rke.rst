.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _rke_install:

********************************************
Installation using Rancher Kubernetes Engine
********************************************

This guide walks you through installation of Cilium on `Rancher Kubernetes Engine <https://rancher.com/products/rke/>`_,
a CNCF-certified Kubernetes distribution that runs entirely within Docker containers.
RKE solves the common frustration of installation complexity with Kubernetes by
removing most host dependencies and presenting a stable path for deployment,
upgrades, and rollbacks.

Install a Cluster Using RKE
===========================

The first step is to install a cluster based on the `RKE Installation Guide <https://rancher.com/docs/rke/latest/en/installation/>`_.
When creating the cluster, make sure to `change the default network plugin <https://rancher.com/docs/rke/latest/en/config-options/add-ons/network-plugins/custom-network-plugin-example/>`_
in the config.yaml file.

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

        .. code-block:: shell-session

            cilium install

.. include:: k8s-install-restart-pods.rst

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst
