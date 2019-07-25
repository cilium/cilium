.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _nodeport:

**************************
Kubernetes NodePort (beta)
**************************

This guide explains how to configure Cilium to enable Kubernetes NodePort
services in BPF which can replace NodePort implemented by ``kube-proxy``.
Enabling the feature allows to run a fully functioning Kubernetes cluster
without ``kube-proxy``.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

.. note::

   NodePort services depend on the :ref:`host-services` feature, therefore
   a v4.19.57, v5.1.16, v5.2.0 or more recent Linux kernel is required.

First step is to download the Cilium Kubernetes descriptor:

.. tabs::

  .. group-tab:: K8s 1.15

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.15/cilium.yaml

  .. group-tab:: K8s 1.14

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.14/cilium.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.13/cilium.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.12/cilium.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml

Next, edit the ``cilium-config`` ConfigMap in that file and set the option
``enable-node-port`` to ``"true"``.

By default, a NodePort service will be accessible via an IP address of a native
device which has a default route on the host. To change a device, set its name
in the ``device`` option.

In addition, thanks to the :ref:`host-services` feature, the NodePort service
can be accessed from a host or a Pod within a cluster via
``127.0.0.1:$NODE_PORT``.

If ``kube-apiserver`` was configured to use a non-default NodePort port range,
then the same range must be passed to Cilium via the ``node-port-range``
ConfigMap option.

Once configured, apply the DaemonSet file to deploy Cilium and verify that it
has come up correctly:

.. parsed-literal::

    kubectl create -f ./cilium.yaml
    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

Limitations
###########

    * Both Service's ``externalTrafficPolicy: Local`` and ``healthCheckNodePort``
      are currently not supported.
