.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

**************************
Installation using kubeadm
**************************

This guide describes deploying Cilium on a Kubernetes cluster created with
``kubeadm``.

For installing ``kubeadm`` on your system, please refer to `the official
kubeadm documentation
<https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/>`_
The official documentation also describes additional options of kubeadm which
are not mentioned here.

If you are interested in using Cilium's kube-proxy replacement, please
follow the :ref:`kubeproxy-free` guide and skip this one.

Create the cluster
==================

Initialize the control plane via executing on it:

.. code-block:: shell-session

   kubeadm init

.. note::
   If you want to use Cilium's kube-proxy replacement, kubeadm needs to skip
   the kube-proxy deployment phase, so it has to be executed with the
   ``--skip-phases=addon/kube-proxy`` option:

   .. code-block:: shell-session

      kubeadm init --skip-phases=addon/kube-proxy

   For more information please refer to the :ref:`kubeproxy-free` guide.

Afterwards, join worker nodes by specifying the control-plane node IP address
and the token returned by ``kubeadm init``:

.. code-block:: shell-session

   kubeadm join <..>

Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| --namespace kube-system

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst
