.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _chaining_oracle_oke:

********************************************************
Oracle Kubernetes Engine (OKE) VCN-Native Pod Networking
********************************************************

This guide explains how to set up Cilium on top of Oracle Kubernetes Engine
(OKE) with VCN-Native Pod Networking. In this hybrid mode, Oracle's CNI stack
is responsible for setting up the virtual network devices and for IP address
management (IPAM) from the VCN subnet. After the initial networking is set up
for a given pod, the Cilium CNI plugin attaches eBPF programs to enforce
network policies, perform load-balancing, and provide visibility.

VCN-Native Pod Networking is Oracle's recommended production CNI mode for OKE.
It assigns pod IPs directly from the VCN subnet, making pods natively routable
without an overlay. This is the Oracle equivalent of AWS VPC CNI or Azure CNI.

.. include:: cni-chaining-limitations.rst

How it works
============

The OKE CNI stack runs two plugins in sequence:

- **oci-ipvlan**: allocates a pod IP from the VCN subnet via OCI IPAM and
  manages VNIC attachment on the underlying compute instance
- **oci-ptp**: creates a veth pair between the pod network namespace and the host

Despite the ``oci-ipvlan`` plugin name, the actual pod-facing interface is a
standard veth pair. Pods receive a VCN-native IP, the host holds a per-pod
veth peer, and routing uses a proxy-ARP gateway at ``169.254.1.1``. This model
is functionally identical to AWS VPC CNI.

Cilium runs as the third plugin in the chain via the ``generic-veth`` chaining
mode. When ``cni.chainingTarget=oci`` is set, the Cilium agent discovers the
existing OCI conflist named ``"oci"`` on each node, merges itself into the
plugin array, and writes the result to ``/etc/cni/net.d/05-cilium.conflist``.
The original ``10-oci.conflist`` is not modified — checking that file will not
show the ``cilium-cni`` entry. Because ``05-cilium.conflist`` sorts before
``10-oci.conflist``, the kubelet picks it up automatically for all new pods.
No manual CNI ConfigMap is required.

Prerequisites
=============

- OKE cluster with VCN-Native Pod Networking enabled (not Flannel)
- ``kubectl`` configured and pointing at the cluster
- Helm v3+

Setting up Cilium
=================

.. include:: k8s-install-download-release.rst

Deploy Cilium via Helm:

.. cilium-helm-install::
   :namespace: kube-system
   :set: cni.chainingTarget=oci
         cni.exclusive=false
         routingMode=native
         enableIPv4Masquerade=false
         kubeProxyReplacement=false
         ipam.mode=cluster-pool
         ipam.operator.clusterPoolIPv4PodCIDRList=100.64.0.0/16

Setting ``cni.chainingTarget=oci`` tells the Cilium agent to find the existing
OCI CNI conflist and inject itself automatically. Tunneling is disabled because
pod IPs are directly routable within the VCN. Masquerading is disabled because
OCI handles routing at the VCN level. ``cni.exclusive=false`` ensures Cilium
does not take ownership of the CNI config directory, leaving OKE's
``vcn-native-ip-cni`` DaemonSet in control.

.. note::

   The ``ipam.operator.clusterPoolIPv4PodCIDRList`` is set to the RFC 6598
   CGNAT range ``100.64.0.0/16``. This does not conflict with VCN subnets and
   is used by Cilium for internal purposes only. Actual pod IPs are always
   assigned by OCI IPAM from the VCN subnet.

.. note::

   OKE runs ``kube-proxy`` by default. The ``kubeProxyReplacement=false`` flag
   leaves it in place. If you want Cilium to replace kube-proxy, follow the
   standard :ref:`kubeproxy-free` guide after the chaining setup is stable.

Restart existing pods
=====================

The new CNI chaining configuration will not apply to pods that were already
running before Cilium was installed. Those pods remain reachable and Cilium
will load-balance to them, but policy enforcement will not apply until they are
restarted.

Use the following to identify pods that need restarting:

.. code-block:: bash

   for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
        ceps=$(kubectl -n "${ns}" get cep \
            -o jsonpath='{.items[*].metadata.name}')
        pods=$(kubectl -n "${ns}" get pod \
            -o custom-columns=NAME:.metadata.name,NETWORK:.spec.hostNetwork \
            | grep -E '\s(<none>|false)' | awk '{print $1}' | tr '\n' ' ')
        ncep=$(echo "${pods} ${ceps}" | tr ' ' '\n' | sort | uniq -u | paste -s -d ' ' -)
        for pod in $(echo $ncep); do
          echo "${ns}/${pod}";
        done
   done

Uninstall
=========

.. code-block:: shell-session

   $ helm uninstall cilium -n kube-system

.. warning::

   ``helm uninstall`` removes Kubernetes resources but does not clean up files
   written to node host paths. The ``/etc/cni/net.d/05-cilium.conflist`` file
   remains on every node after uninstall. Because it sorts before
   ``10-oci.conflist``, the kubelet continues to use it for new pod creations.
   With the Cilium agent gone, ``cilium-cni`` cannot reach its socket and
   **new pods will be stuck in ContainerCreating** with the error
   ``dial unix /var/run/cilium/cilium.sock: connect: no such file or directory``.
   Existing running pods are not affected since CNI is only called at pod
   creation time.

   After uninstalling, SSH into each node and remove the file:

   .. code-block:: shell-session

      $ sudo rm -f /etc/cni/net.d/05-cilium.conflist

   OKE's ``vcn-native-ip-cni`` DaemonSet will then handle all new pod
   networking via ``10-oci.conflist``.

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst
