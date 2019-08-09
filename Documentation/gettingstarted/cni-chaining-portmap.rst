.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

******************
Portmap (HostPort)
******************

If you want to use the Kubernetes HostPort feature, you must enable CNI
chaining with the portmap plugin which implements HostPort. This guide
documents how to do so.  For more information about the Kubernetes HostPort
feature , check out the upstream documentation:
`Kubernetes hostPort-CNI plugin documentation
<https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-hostport>`_.

.. note::

   Before using HostPort, read the `Kubernetes Configuration Best Practices
   <https://kubernetes.io/docs/concepts/configuration/overview/>`_ to
   understand the implications of this feature.

Deploy Cilium with the portmap plugin enabled
=============================================

.. include:: k8s-install-download-release.rst

Generate the required YAML file and deploy it:

.. code:: bash

    helm template cilium \
      --namespace=kube-system \
      --set global.cni.chainingMode=portmap \
      > cilium.yaml
    kubectl create -f cilium.yaml

.. note::

   You can combine the ``global.cni.chainingMode=portmap`` option with any of
   the other installation guides.

As Cilium is deployed as a DaemonSet, it will write a new CNI configuration
``05-cilium.conflist`` and remove the standard ``05-cilium.conf``. The new
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
