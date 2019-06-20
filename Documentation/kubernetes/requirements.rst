.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _k8s_requirements:

************
Requirements
************

Kubernetes Version
==================

The following Kubernetes versions have been tested in the continuous integration
system for this version of Cilium:

* 1.10
* 1.11
* 1.12
* 1.13
* 1.14
* 1.15

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

.. _admin_mount_bpffs:

Mounted BPF filesystem
======================

This step is optional but recommended. It allows the ``cilium-agent`` to pin
BPF resources to a persistent filesystem and make them persistent across
restarts of the agent. If the BPF filesystem is not mounted in the host
filesystem, Cilium will automatically mount the filesystem but it will be
unmounted and re-mounted when the Cilium pod is restarted. This in turn will
cause BPF resources to be re-created which will cause network connectivity to
be disrupted.  Mounting the BPF filesystem in the host mount namespace will
ensure that the agent can be restarted without affecting connectivity of any
pods.

In order to mount the BPF filesystem, the following command must be run in the
host mount namespace. The command must only be run once during the boot process
of the machine.

.. code:: bash

	mount bpffs /sys/fs/bpf -t bpf

A portable way to achieve this with persistence is to add the following line to
``/etc/fstab`` and then run ``mount /sys/fs/bpf``. This will cause the
filesystem to be automatically mounted when the node boots.

.. code:: bash

     bpffs			/sys/fs/bpf		bpf	defaults 0 0

If you are using systemd to manage the kubelet, see the section
:ref:`bpffs_systemd`.

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
