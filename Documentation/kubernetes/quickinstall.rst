.. _k8s_quick:

***********
Quick Start
***********

If you know what you are doing, then the following quick instructions get you
started in the shortest time possible. If you require additional details or are
looking to customize the installation then read the remaining sections of this
chapter.

1. Mount the BPF filesystem on all k8s worker nodes. There are many ways to
   achieve this, see section :ref:`admin_mount_bpffs` for more details.

.. code:: bash

	mount bpffs /sys/fs/bpf -t bpf

2. Download the `DaemonSet` template ``cilium.yaml`` and specify the etcd address:

.. tabs::
  .. group-tab:: K8s 1.7

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.7/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]

  .. group-tab:: K8s 1.8

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.8/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.9/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]


**Optional:** If you want to adjust the MTU of the pods, define the ``MTU`` environment
variable in the ``env`` section:

.. code:: bash

    env:
      - name: "MTU"
        value: "8950"

3. Deploy ``cilium`` with your local changes

.. code:: bash

    $ kubectl create -f ./cilium.yaml
    clusterrole "cilium" created
    serviceaccount "cilium" created
    clusterrolebinding "cilium" created
    configmap "cilium-config" created
    secret "cilium-etcd-secrets" created
    daemonset "cilium" created

    $ kubectl get ds --namespace kube-system
    NAME            DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
    cilium          1         1         1         <none>          2m

You have cilium deployed in your cluster and ready to use.
