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

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

    The feature lacks support of the following, which will be resolved in
    upcoming Cilium releases:

    - L7 policy enforcement


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

Generate the required YAML file and deploy it:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.flannel.enabled=true \
     > cilium.yaml

Set ``global.flannel.uninstallOnExit=true`` if you want Cilium to uninstall
itself when the Cilium pod is stopped.

If the Flannel bridge has a different name than ``cni0``, you must specify
the name by setting ``global.flannel.masterDevice=...``.

*Optional step:*
If your cluster has already pods being managed by Flannel, there is also
an option available that allows Cilium to start managing those pods without
requiring to restart them. To enable this functionality you need to set the
value ``global.flannel.manageExistingContainers=true``

Once you have changed the ConfigMap accordingly, you can deploy Cilium.

.. parsed-literal::

   kubectl create -f cilium.yaml

Cilium might not come up immediately on all nodes, since Flannel only sets up
the bridge network interface that connects containers with the outside world
when the first container is created on that node. In this case, Cilium will wait
until that bridge is created before marking itself as Ready.
