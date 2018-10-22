.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

Cilium, Kubernetes and CRI-O
============================


Step 1: Install Cilium with CRI-O
=================================

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

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-crio.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-crio.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-crio.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-crio.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-crio.yaml
      configmap "cilium-config" created
      secret "cilium-etcd-secrets" created
      daemonset.extensions "cilium" created
      clusterrolebinding.rbac.authorization.k8s.io "cilium" created
      clusterrole.rbac.authorization.k8s.io "cilium" created
      serviceaccount "cilium" created

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-crio.yaml
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

Since CRI-O does not automatically detect that a new CNI plugin has been
installed, you will need to restart the CRI-O daemon for it to pick up the
Cilium CNI configuration.

First make sure cilium is running:

::

    $ kubectl get pods -n kube-system -o wide
    NAME               READY     STATUS    RESTARTS   AGE       IP          NODE
    cilium-mqtdz       1/1       Running   0          3m       10.0.2.15   minikube

After that you can restart CRI-O:

::

    $ minikube ssh -- sudo systemctl restart crio

Finally, you need to restart the Cilium pod so it can re-mount
``/var/run/crio.sock`` which was recreated by CRI-O

::

    $ kubectl delete -n kube-system pod cilium-mqtdz
