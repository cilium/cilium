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

If you instead want to understand the details of
deploying Cilium on a full fledged Kubernetes cluster, then go straight to
:ref:`admin_install_daemonset`.

.. include:: gsg_intro.rst
.. include:: minikube_intro.rst
.. include:: cilium_install.rst
.. include:: gsg_starwars.rst
