.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

*********
Azure CNI
*********

This guide explains how to set up Cilium in combination with Azure CNI. In this
hybrid mode, the Azure CNI plugin is responsible for setting up the virtual
network devices as well as address allocation (IPAM). After the initial
networking is setup, the Cilium CNI plugin is called to attach BPF programs to
the network devices set up by Azure CNI to enforce network policies, perform
load-balancing, and encryption.

.. note::

   If you are looking to install Cilium on Azure AKS, see the guide
   :ref:`k8s_install_aks` for a complete guide also covering cluster setup.

.. include:: k8s-install-azure-cni-steps.rst

Restart existing pods
=====================

The new CNI chaining configuration will *not* apply to any pod that is already
running in the cluster. Existing pods will be reachable and Cilium will
load-balance to them but policy enforcement will not apply to them and
load-balancing is not performed for traffic originating from existing pods.
You must restart these pods in order to invoke the chaining configuration on
them.

If you are unsure if a pod is managed by Cilium or not, run ``kubectl get cep``
in the respective namespace and see if the pod is listed.

.. include:: k8s-install-azure-cni-validate.rst
.. include:: hubble-enable.rst

