.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io


.. _k8s_install_portmap:

******************
Portmap (HostPort)
******************

Starting from Cilium 1.8, the Kubernetes HostPort feature is supported natively
through Cilium's eBPF-based kube-proxy replacement. CNI chaining is therefore
not needed anymore. For more information, see section :ref:`kubeproxyfree_hostport`.

However, for the case where Cilium is deployed as ``kubeProxyReplacement=disabled``,
the HostPort feature can then be enabled via CNI chaining with the portmap plugin which
implements HostPort. This guide documents how to enable the latter for the chaining
case.

For more general information about the Kubernetes HostPort feature, check out the
upstream documentation:
`Kubernetes hostPort-CNI plugin documentation
<https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-hostport>`_.

.. note::

   Before using HostPort, read the `Kubernetes Configuration Best Practices
   <https://kubernetes.io/docs/concepts/configuration/overview/>`_ to
   understand the implications of this feature.

Deploy Cilium with the portmap plugin enabled
=============================================

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
      --namespace=kube-system \\
      --set cni.chainingMode=portmap

.. note::

   You can combine the ``cni.chainingMode=portmap`` option with any of
   the other installation guides.

As Cilium is deployed as a DaemonSet, it will write a new CNI configuration. The new
configuration now enables HostPort. Any new pod scheduled is now able to make
use of the HostPort functionality.

Restart existing pods
=====================

The new CNI chaining configuration will *not* apply to any pod that is already
running the cluster. Existing pods will be reachable and Cilium will
load-balance to them but policy enforcement will not apply to them and
load-balancing is not performed for traffic originating from existing pods.
You must restart these pods in order to invoke the chaining configuration on
them.
