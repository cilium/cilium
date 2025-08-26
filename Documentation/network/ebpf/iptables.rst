.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

##############
Iptables Usage
##############

Depending on the Linux kernel version being used, the eBPF datapath can
implement a varying feature set fully in eBPF. If certain required capabilities
are not available, the functionality is provided using a legacy iptables
implementation. See :ref:`features_kernel_matrix` for more details.


kube-proxy Interoperability
===========================

The following diagram shows the integration of iptables rules as installed by
kube-proxy and the iptables rules as installed by Cilium.

.. image:: _static/kubernetes_iptables.svg
