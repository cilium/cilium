.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _gs_minikube:

******************************
Getting Started Using Minikube
******************************

This guide uses `minikube <https://kubernetes.io/docs/getting-started-guides/minikube/>`_
to demonstrate deployment and operation of Cilium in a single-node Kubernetes cluster.
The minikube VM requires approximately 5GB of RAM and supports hypervisors like VirtualBox
that run on Linux, macOS, and Windows.

Install kubectl & minikube
==========================

1. Install ``kubectl`` version >= v1.8.0 as described in the `Kubernetes Docs <https://kubernetes.io/docs/tasks/tools/install-kubectl/>`_.

2. Install ``minikube`` >= v0.33.1 as per minikube documentation: `Install Minikube <https://kubernetes.io/docs/tasks/tools/install-minikube/>`_.

::

     minikube version
     minikube version: v0.33.1

3. Create a minikube cluster:

::

     minikube start --network-plugin=cni --memory=4096

Note that in case of installing Cilium for a specific Kubernetes version, the
``--kubernetes-version vx.y.z`` parameter can be appended to the ``minikube start``
command for bootstrapping the local cluster. By default, minikube will install
the most recent version of Kubernetes.

Install Cilium
==============

Install Cilium as `DaemonSet
<https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/>`_ into
your new Kubernetes cluster. The DaemonSet will automatically install itself as
Kubernetes CNI plugin.

.. tabs::
  .. group-tab:: K8s 1.13

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-minikube.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-minikube.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-minikube.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-minikube.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-minikube.yaml

  .. group-tab:: K8s 1.8

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-minikube.yaml

Next steps
==========

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`
