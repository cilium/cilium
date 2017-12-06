Step 1: Install Cilium
======================

The next step is to install Cilium into your Kubernetes cluster.
Cilium installation leverages the `Kubernetes Daemon Set
<https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/>`_
abstraction, which will deploy one Cilium pod per cluster node.  This
Cilium pod will run in the ``kube-system`` namespace along with all
other system relevant daemons and services.  The Cilium pod will run
both the Cilium agent and the Cilium CNI plugin.

To deploy Cilium, run:

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/cilium.yaml
    configmap "cilium-config" created
    secret "cilium-etcd-secrets" created
    serviceaccount "cilium" created
    clusterrolebinding "cilium" created
    daemonset "cilium" created
    clusterrole "cilium" created

Kubernetes is now deploying Cilium with its RBAC settings, ConfigMap
and DaemonSet as a pod on minkube. This operation is performed in the
background.

Run the following command to check the progress of the deployment:

::

    $ kubectl get daemonsets -n kube-system
    NAME      DESIRED   CURRENT   READY     UP-TO-DATE   AVAILABLE   NODE-SELECTOR   AGE
    cilium    1         1         0         1            0           <none>          6s
    
Wait until the cilium Deployment shows a ``CURRENT`` count of ``1``
like above (a ``READY`` value of ``0`` is OK for this tutorial).
