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

    $ minikube start --network-plugin=cni --extra-config=kubelet.network-plugin=cni --memory=4096

After minikube has finished setting up your new Kubernetes cluster, you can
check the status of the cluster by running ``kubectl get cs``:

::

    $ kubectl get cs
    NAME                 STATUS    MESSAGE              ERROR
    controller-manager   Healthy   ok
    scheduler            Healthy   ok
    etcd-0               Healthy   {"health": "true"}


4. Install etcd as a dependency of cilium in minikube by running:

.. parsed-literal::

  $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/addons/etcd/standalone-etcd.yaml
  service "etcd-cilium" created
  statefulset.apps "etcd-cilium" created

To check that all pods are ``Running`` and 100% ready, including ``kube-dns``
and ``etcd-cilium-0`` run:

::

    $ kubectl get pods --all-namespaces
    NAMESPACE     NAME                               READY     STATUS    RESTARTS   AGE
    default       etcd-cilium-0                      1/1       Running   0          1m
    kube-system   etcd-minikube                      1/1       Running   0          3m
    kube-system   kube-addon-manager-minikube        1/1       Running   0          4m
    kube-system   kube-apiserver-minikube            1/1       Running   0          3m
    kube-system   kube-controller-manager-minikube   1/1       Running   0          3m
    kube-system   kube-dns-86f4d74b45-lhzfv          3/3       Running   0          4m
    kube-system   kube-proxy-tcd7h                   1/1       Running   0          4m
    kube-system   kube-scheduler-minikube            1/1       Running   0          4m
    kube-system   storage-provisioner                1/1       Running   0          4m

If you see output similar to this, you are ready to proceed to the next step.

.. note::

    The output might differ between minikube versions, you should expect to have
    all pods in READY / Running state before continuing.
