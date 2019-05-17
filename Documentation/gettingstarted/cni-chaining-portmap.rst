.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

******************
Portmap (HostPort)
******************

If you want to use the Kubernetes HostPort feature, you must enable CNI
chaining with the portmap plugin which implements HostPort. This guide
documents how to do so.  For more information about HostPort, check the
`Kubernetes hostPort-CNI plugin documentation
<https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-hostport>`_.


.. note::

   Before using HostPort, read the `Kubernetes Configuration Best Practices
   <https://kubernetes.io/docs/concepts/configuration/overview/>`_ to
   understand the implications of this feature.

Enable Portmap Chaining in the ConfigMap
========================================

1. If you have not deployed Cilium yet, download the Cilium deployment yaml:

.. tabs::
  .. group-tab:: K8s 1.14

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.14/cilium.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.13/cilium.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.12/cilium.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml

2. If you are already running Cilium, extract the ConfigMap of Cilium:

   .. code:: bash

       kubectl -n kube-system get cm cilium-config -o yaml > cilium.yaml

3. Edit ``cilium.yaml`` and add the following configuration to the ConfigMap:

   .. code:: bash

          cni-chaining-mode: portmap

4. Deploy or update Cilium:

   .. code:: bash

          kubectl apply -f cilium.yaml

   As Cilium is deployed as a DaemonSet, it will write a new CNI configuration
   ``05-cilium.conflist`` and remove the standard ``05-cilium.conf``. The new
   configuration now enables HostPort. Any new pod scheduled is now able to
   make use of the HostPort functionality.

Restart existing pods
=====================

The new CNI chaining configuration will *not* apply to any pod that is already
running the cluster. Existing pods will be reachable and Cilium will
load-balance to them but policy enforcement will not apply to them and
load-balancing is not performed for traffic originating from existing pods.
You must restart these pods in order to invoke the
chaining configuration on them.
