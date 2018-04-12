Step 0: Install kubectl & minikube
==================================

1. Install ``kubectl`` version ``>= 1.7.0`` as described in the
`Kubernetes Docs
<https://kubernetes.io/docs/tasks/tools/install-kubectl/>`_.

2. Install one of the `hypervisors supported by minikube
   <https://kubernetes.io/docs/tasks/tools/install-minikube/>`_.

3. Install ``minikube`` ``>= 0.22.3`` as described on `minikube's
github page <https://github.com/kubernetes/minikube/releases>`_.

Boot a minikube cluster with the Container Network Interface (CNI) network
plugin, the ``localkube`` bootstrapper.

The ``localkube`` bootstrapper provides ``etcd`` >= ``3.1.0``, a cilium
dependency.

::

    $ minikube start --network-plugin=cni --bootstrapper=localkube --memory=4096 --extra-config=apiserver.Authorization.Mode=RBAC

After minikube has finished setting up your new Kubernetes cluster, you can
check the status of the cluster by running ``kubectl get cs``:

::

    $ kubectl get cs
    NAME                 STATUS    MESSAGE              ERROR
    controller-manager   Healthy   ok
    scheduler            Healthy   ok
    etcd-0               Healthy   {"health": "true"}

Bind the Kubernetes system account to the ``cluster-admin`` role to enable the
``kube-dns`` service to run with RBAC enabled:

::

    $ kubectl create clusterrolebinding kube-system-default-binding-cluster-admin --clusterrole=cluster-admin --serviceaccount=kube-system:default

To check that all Kubernetes pods are ``Running`` and 100% ready,
including ``kube-dns``, run:

::

    $ kubectl get pods -n kube-system
    NAME                          READY     STATUS    RESTARTS   AGE
    kube-addon-manager-minikube   1/1       Running   0          59s
    kube-dns-86f6f55dd5-5xdz8     3/3       Running   0          55s
    storage-provisioner           1/1       Running   0          56s

If you see output similar to this, you are ready to proceed to the
next step.