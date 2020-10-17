.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _flannel-integration:

**************************************
Cilium integration with Flannel (beta)
**************************************

.. warning::

   Since availability of :ref:`cni_chaining` the recommended way to run Cilium on top of Flannel is :ref:`generic_veth_cni_chaining`.

This guide contains the necessary steps to run Cilium on top of your Flannel
cluster.

If you have a cluster already set up with Flannel you will not need to install
Flannel again.

This Cilium integration with Flannel was performed with Flannel 0.10.0 and
Kubernetes >= 1.9. If you find any issues with previous Flannel versions please
feel free to reach out to us to help you.

.. include:: ../beta.rst

Flannel installation
--------------------

NOTE: If ``kubeadm`` is used, then pass ``--pod-network-cidr=10.244.0.0/16`` to
``kubeadm init`` to ensure that the ``podCIDR`` is set.

.. parsed-literal::

  kubectl apply -f  \ |SCM_WEB|\/examples/kubernetes/addons/flannel/flannel.yaml


Wait until all pods to be in ready state before preceding to the next step.

Cilium installation
-------------------

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set flannel.enabled=true

Set ``flannel.uninstallOnExit=true`` if you want Cilium to uninstall
itself when the Cilium pod is stopped.

If the Flannel bridge has a different name than ``cni0``, you must specify
the name by setting ``flannel.masterDevice=...``.

Cilium might not come up immediately on all nodes, since Flannel only sets up
the bridge network interface that connects containers with the outside world
when the first container is created on that node. In this case, Cilium will wait
until that bridge is created before marking itself as Ready.

Limitations
-----------

Flannel chaining lacks support of the following:

- L7 policy enforcement
