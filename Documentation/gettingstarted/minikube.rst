.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_minikube:

******************************
Getting Started Using Minikube
******************************

This guide uses `minikube <https://kubernetes.io/docs/setup/learning-environment/minikube/>`_
to demonstrate deployment and operation of Cilium in a single-node Kubernetes cluster.
The minikube VM requires approximately 5GB of RAM and supports hypervisors like VirtualBox
that run on Linux, macOS, and Windows.

Install kubectl & minikube
==========================

.. include:: minikube-install.rst
.. include:: quick-install.rst
.. include:: k8s-install-validate.rst
.. include:: namespace-kube-system.rst
.. include:: hubble-enable.rst

Next steps
==========

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`
