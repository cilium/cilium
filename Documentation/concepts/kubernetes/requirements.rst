.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_requirements:

************
Requirements
************

Kubernetes Version
==================

All Kubernetes versions listed are e2e tested and guaranteed to be compatible
with this Cilium version. Older Kubernetes versions not listed here do not have
Cilium support. Newer Kubernetes versions, while not listed, will depend on the
backward compatibility offered by Kubernetes.

* 1.13
* 1.14
* 1.15
* 1.16
* 1.17
* 1.18
* 1.19
* 1.20

System Requirements
===================

Cilium requires a Linux kernel >= 4.9. See :ref:`admin_system_reqs` for the
full details on all systems requirements.

Enable CNI in Kubernetes
========================

`CNI` - Container Network Interface is the plugin layer used by Kubernetes to
delegate networking configuration. CNI must be enabled in your Kubernetes
cluster in order to install Cilium. This is done by passing
``--network-plugin=cni`` to kubelet on all nodes. For more information, see
the `Kubernets CNI network-plugins documentation <https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/>`_.

.. _k8s_req_kubedns:

kube-dns
========

The :ref:`k8s_install_etcd_operator` relies on the etcd-operator to manage an
etcd cluster. In order for the etcd cluster to be available, the Cilium pod is
being run with ``dnsPolicy: ClusterFirstWithHostNet`` in order for Cilium to be
able to look up Kubernetes service names via DNS. This creates a dependency on
kube-dns. If you would like to avoid running kube-dns, choose a different
installation method and remove the ``dnsPolicy`` field from the ``DaemonSet``.

Enable automatic node CIDR allocation (Recommended)
===================================================

Kubernetes has the capability to automatically allocate and assign a per node IP
allocation CIDR. Cilium automatically uses this feature if enabled. This is the
easiest method to handle IP allocation in a Kubernetes cluster. To enable this
feature, simply add the following flag when starting
``kube-controller-manager``:

.. code:: bash

        --allocate-node-cidrs

This option is not required but highly recommended.
