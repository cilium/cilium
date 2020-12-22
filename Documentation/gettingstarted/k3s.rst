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

This guide assumes installation on amd64 architecture. Cilium is presently
supported on amd64 architecture with `ARM support planned <https://github.com/cilium/cilium/issues/9898>`_
for a future release.

Install a Master Node
=====================

The first step is to install a K3s master node making sure to disable support
for the default CNI plugin:

.. parsed-literal::

    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--flannel-backend=none --no-flannel' sh -

Install Agent Nodes (Optional)
==============================

K3s can run in standalone mode or as a cluster making it a great choice for
local testing with multi-node data paths. Agent nodes are joined to the master
node using a node-token which can be found on the master node at
``/var/lib/rancher/k3s/server/node-token``.

Install K3s on agent nodes and join them to the master node making sure to
replace the variables with values from your environment:

.. parsed-literal::

    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--disable-network-policy --no-flannel' K3S_URL='https://${MASTER_IP}:6443' K3S_TOKEN=${NODE_TOKEN} sh -

Should you encounter any issues during the installation, please refer to the
:ref:`troubleshooting_k8s` section and / or seek help on the `Slack channel`.

Please consult the Kubernetes :ref:`k8s_requirements` for information on  how
you need to configure your Kubernetes cluster to operate with Cilium.

Mount the eBPF Filesystem
=========================
On each node, run the following to mount the eBPF Filesystem:
::

     sudo mount bpffs -t bpf /sys/fs/bpf

.. include:: quick-install.rst
.. include:: k8s-install-restart-pods.rst
.. include:: k8s-install-validate.rst
.. include:: namespace-kube-system.rst
.. include:: hubble-enable.rst

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`
