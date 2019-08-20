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

1. Install ``kubectl`` version >= v1.10.0 as described in the `Kubernetes Docs <https://kubernetes.io/docs/tasks/tools/install-kubectl/>`_.

2. Install ``minikube`` >= v1.3.1 as per minikube documentation: `Install Minikube <https://kubernetes.io/docs/tasks/tools/install-minikube/>`_.

.. note::

   It is important to validate that you have minikube v1.3.1 installed. Older
   versions of minikube are shipping a kernel configuration that is *not*
   compatible with the TPROXY requirements of Cilium >= 1.6.0.

::

     minikube version
     minikube version: v1.3.1
     commit: ca60a424ce69a4d79f502650199ca2b52f29e631

3. Create a minikube cluster:

::

     minikube start --network-plugin=cni --memory=4096

4. Mount the BPF filesystem

::

     minikube ssh -- sudo mount bpffs -t bpf /sys/fs/bpf

.. note::

   In case of installing Cilium for a specific Kubernetes version, the
   ``--kubernetes-version vx.y.z`` parameter can be appended to the ``minikube
   start`` command for bootstrapping the local cluster. By default, minikube
   will install the most recent version of Kubernetes.

Install Cilium
==============

Install Cilium as `DaemonSet
<https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/>`_ into
your new Kubernetes cluster. The DaemonSet will automatically install itself as
Kubernetes CNI plugin.

.. parsed-literal::

    kubectl create -f \ |SCM_WEB|\/install/kubernetes/quick-install.yaml

.. include:: k8s-install-validate.rst


Next steps
==========

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`
