Step 0: Install kubectl & minikube
==================================

1. Install ``kubectl`` version ``>= 1.7.0`` as described in the `Kubernetes Docs
<https://kubernetes.io/docs/tasks/tools/install-kubectl/>`_.

2. Install one of the `hypervisors supported by minikube <https://kubernetes.io/docs/tasks/tools/install-minikube/>`_.

3. Install ``minikube`` ``>= 0.22.3`` as described on `minikube's github page
<https://github.com/kubernetes/minikube/releases>`_.

Boot a minukube cluster with the Container Network Interface (CNI) network
plugin, the ``localkube`` bootstrapper, and ``CustomResourceValidation``.

The ``localkube`` bootstrapper provides ``etcd`` >= ``3.1.0``, a cilium
dependency. ``CustomResourceValidation`` will allow Cilium to install the Cilium
Network Policy validator into kubernetes
(`more info <https://kubernetes.io/docs/tasks/access kubernetes-api/extend-api-custom-resource-definitions/#validation>`_).

::

    $ minikube start --network-plugin=cni --bootstrapper=localkube --feature-gates=CustomResourceValidation=true

After minikube has finished  setting up your new Kubernetes cluster, you can
check the status of the cluster by running ``kubectl get cs``:

::

    $ kubectl get cs
    NAME                 STATUS    MESSAGE              ERROR
    controller-manager   Healthy   ok
    scheduler            Healthy   ok
    etcd-0               Healthy   {"health": "true"}

If you see output similar to this, you are ready to proceed to the next step.
