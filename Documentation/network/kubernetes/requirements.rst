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

* 1.19
* 1.20
* 1.21
* 1.22
* 1.23
* 1.24
* 1.25
* 1.26
* 1.27

System Requirements
===================

See :ref:`admin_system_reqs` for all of the Cilium system requirements.

Enable CNI in Kubernetes
========================

:term:`CNI` - Container Network Interface is the plugin layer used by Kubernetes to
delegate networking configuration. Prior to Kubernetes 1.24, the CNI plugins could also be managed by the kubelet using the ``cni-bin-dir`` and ``network-plugin`` command-line parameters. These command-line parameters were removed in Kubernetes 1.24, with management of the CNI no longer in scope for kubelet.
 For more information, see the `Kubernetes CNI network-plugins documentation <https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/>`_. To enable the cilium CNI plugin you need to configure the CNI plugin located at ``/etc/cni/net.d/`` . you can do this by making a config file for at the designated location . for making a config file you can refer to : `cilium config documentation <https://docs.cilium.io/en/stable/configuration/>`_. 

Enable automatic node CIDR allocation (Recommended)
===================================================

Kubernetes has the capability to automatically allocate and assign a per node IP
allocation CIDR. Cilium automatically uses this feature if enabled. This is the
easiest method to handle IP allocation in a Kubernetes cluster. To enable this
feature, simply add the following flag when starting
``kube-controller-manager``:

.. code-block:: shell-session

        --allocate-node-cidrs

This option is not required but highly recommended.
