.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

Cilium, Kubernetes and Docker
=============================

Step 1: Install Cilium with Docker
==================================

The next step is to install Cilium into your Kubernetes cluster.
Cilium installation leverages the `Kubernetes Daemon Set
<https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/>`_
abstraction, which will deploy one Cilium pod per cluster node.  This
Cilium pod will run in the ``kube-system`` namespace along with all
other system-relevant daemons and services.  The Cilium pod will run
both the Cilium agent and the Cilium CNI plugin.

To deploy Cilium, run:

.. tabs::
  .. group-tab:: K8s 1.8

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

Kubernetes is now deploying Cilium with its RBAC settings, ConfigMap
and DaemonSet as a pod on minikube. This operation is performed in the
background.

Run the following command to check the progress of the deployment:

::

    $ kubectl get daemonsets -n kube-system
    NAME         DESIRED   CURRENT   READY     UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
    cilium       1         1         0         1            1           <none>          3m
    kube-proxy   1         1         1         1            1           <none>          8m

Wait until the cilium Deployment shows a ``CURRENT`` count of ``1``
like above (a ``READY`` value of ``0`` is OK for this tutorial).
