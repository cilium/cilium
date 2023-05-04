.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k3s_install:

**********************
Installation Using K3s
**********************

This guide walks you through installation of Cilium on `K3s <https://k3s.io/>`_,
a highly available, certified Kubernetes distribution designed for production
workloads in unattended, resource-constrained, remote locations or inside IoT
appliances.

Cilium is presently supported on amd64 and arm64 architectures.

Install a Master Node
=====================

The first step is to install a K3s master node making sure to disable support
for the default CNI plugin and the built-in network policy enforcer:

.. note::

   If running Cilium in :ref:`kubeproxy-free` mode, add option ``--disable-kube-proxy``

.. code-block:: shell-session

    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--flannel-backend=none --disable-network-policy' sh -

Install Agent Nodes (Optional)
==============================

K3s can run in standalone mode or as a cluster making it a great choice for
local testing with multi-node data paths. Agent nodes are joined to the master
node using a node-token which can be found on the master node at
``/var/lib/rancher/k3s/server/node-token``.

Install K3s on agent nodes and join them to the master node making sure to
replace the variables with values from your environment:

.. code-block:: shell-session

    curl -sfL https://get.k3s.io | K3S_URL='https://${MASTER_IP}:6443' K3S_TOKEN=${NODE_TOKEN} sh -

Should you encounter any issues during the installation, please refer to the
:ref:`troubleshooting_k8s` section and / or seek help on the :term:`Slack channel`.

Please consult the Kubernetes :ref:`k8s_requirements` for information on  how
you need to configure your Kubernetes cluster to operate with Cilium.

Configure Cluster Access
========================

For the Cilium CLI to access the cluster in successive steps you will need to
use the ``kubeconfig`` file stored at ``/etc/rancher/k3s/k3s.yaml`` by setting
the ``KUBECONFIG`` environment variable:

.. code-block:: shell-session

    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

Install Cilium
==============

.. include:: cli-download.rst

.. note::

   Install Cilium with ``--helm-set=ipam.operator.clusterPoolIPv4PodCIDR="10.42.0.0/16"`` to match k3s default podCIDR 10.42.0.0/16.

Install Cilium by running:

.. code-block:: shell-session

    cilium install --helm-set=ipam.operator.clusterPoolIPv4PodCIDR="10.42.0.0/16"

Validate the Installation
=========================

.. include:: cli-status.rst
.. include:: cli-connectivity-test.rst

.. include:: next-steps.rst

