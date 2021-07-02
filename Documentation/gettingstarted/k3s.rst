.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k3s_install:

*************************
Getting Started Using K3s
*************************

This guide walks you through installation of Cilium on `K3s <https://k3s.io/>`_,
a highly available, certified Kubernetes distribution designed for production
workloads in unattended, resource-constrained, remote locations or inside IoT
appliances.

Cilium is presently supported on amd64 and arm64 architectures.

Install a Master Node
=====================

The first step is to install a K3s master node making sure to disable support
for the default CNI plugin and the built-in network policy enforcer:

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
:ref:`troubleshooting_k8s` section and / or seek help on the `Slack channel`.

Please consult the Kubernetes :ref:`k8s_requirements` for information on  how
you need to configure your Kubernetes cluster to operate with Cilium.

Mount the eBPF Filesystem
=========================
On each node, run the following to mount the eBPF Filesystem:

.. code-block:: shell-session

     sudo mount bpffs -t bpf /sys/fs/bpf

Install Cilium
==============

.. include:: cli-download.rst

Install Cilium by running:

.. code-block:: shell-session

    cilium install

Validate the Installation
=========================

.. include:: cli-status.rst
.. include:: cli-connectivity-test.rst

.. include:: next-steps.rst

