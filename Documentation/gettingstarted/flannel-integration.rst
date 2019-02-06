.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _flannel-integration:

**************************************
Cilium integration with Flannel (beta)
**************************************

This guide contains the necessary steps to run Cilium on top of your Flannel
cluster.

If you have a cluster already set up with Flannel you will not need to install
Flannel again.

This Cilium integration with Flannel was performed with Flannel 0.10.0 and
Kubernetes >= 1.9. If you find any issues with previous Flannel versions please
feel free to reach out to us to help you.

Flannel installation
--------------------

NOTE: If ``kubeadm`` is used, then pass ``--pod-network-cidr=10.244.0.0/16`` to
``kubeadm init`` to ensure that the ``podCIDR`` is set.

.. parsed-literal::

  kubectl -f  \ |SCM_WEB|\/examples/kubernetes/addons/flannel/flannel.yaml


Wait until all pods to be in ready state before preceding to the next step.

Cilium installation
-------------------

Download Cilium kubernetes descriptor for your Kubernetes version.


.. tabs::
  .. group-tab:: K8s 1.13

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.13/cilium.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.12/cilium.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.9/cilium.yaml

  .. group-tab:: K8s 1.8

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.8/cilium.yaml

Edit the ConfigMap in that file and set the option ``flannel-master-device`` with ``"cni0"``.

Set ``flannel-uninstall-on-exit`` with either ``true`` or ``false``. If you
plan to deploy Cilium and ensure that policy enforcement will persist even if
you remove Cilium, then leave the option set to ``false``. If you plan to test
Cilium in your cluster and remove Cilium once you have finished your tests,
setting the option with ``true`` will make sure the Cilium will clean up all BPF
programs generated for the host where Cilium was running.

*Optional step:*
If your cluster has already pods being managed by Flannel, there is also
an option available that allows Cilium to start managing those pods without
requiring to restart them. To enable this functionality you need to set the
value ``flannel-manage-existing-containers`` to ``true`` **and** modify
the ``hostPID`` value in the Cilium DaemonSet to ``true``. Running
Cilium with ``hostPID`` is required because Cilium needs to access the network
namespaces of those already running pods in order to derive the MAC address and
IP address which allows the generation dedicated BPF programs for those pods.


::

  # Interface to be used when running Cilium on top of a CNI plugin.
  # For flannel, use "cni0"
  flannel-master-device: "cni0"
  # When running Cilium with policy enforcement enabled on top of a CNI plugin
  # the BPF programs will be installed on the network interface specified in
  # 'flannel-master-device' and on all network interfaces belonging to
  # a container. When the Cilium DaemonSet is removed, the BPF programs will
  # be kept in the interfaces unless this option is set to "true".
  flannel-uninstall-on-exit: "false"
  # Installs a BPF program to allow for policy enforcement in already running
  # containers managed by Flannel.
  # NOTE: This requires Cilium DaemonSet to be running in the hostPID.
  # To run in this mode in Kubernetes change the value of the hostPID from
  # false to true. Can be found under the path `spec.spec.hostPID`
  flannel-manage-existing-containers: "false"


Once you have changed the ConfigMap accordingly, you can deploy Cilium.

.. parsed-literal::

    kubectl create -f ./cilium.yaml

Cilium might not come up immediately on all nodes, since Flannel only sets up
the bridge network interface that connects containers with the outside world
when the first container is created on that node. In this case, Cilium will wait
until that bridge is created before marking itself as Ready.
