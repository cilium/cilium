.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

Step 0: Install kubectl & minikube
==================================

1. Install ``kubectl`` version ``>= 1.8.0`` as described in the `Kubernetes Docs <https://kubernetes.io/docs/tasks/tools/install-kubectl/>`_.

2. Install one of the `hypervisors supported by minikube <https://kubernetes.io/docs/tasks/tools/install-minikube/>`_ .

3. Install ``minikube`` ``>= 0.22.3`` as described on `minikube's github page <https://github.com/kubernetes/minikube/releases>`_ .

.. tabs::
  .. group-tab:: docker

    .. parsed-literal::

      minikube start --network-plugin=cni --extra-config=kubelet.network-plugin=cni --memory=5120

  .. group-tab:: cri-o

    .. parsed-literal::

      minikube start --network-plugin=cni --container-runtime=cri-o --extra-config=kubelet.network-plugin=cni --memory=5120
