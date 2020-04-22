.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Cilium will manage ENIs instead of VPC CNI, so the ``aws-node`` DaemonSet
has to be deleted to prevent conflict behavior.

.. note::

   Once ``aws-node`` DaemonSet is deleted, EKS will not try to restore it.

.. code:: bash

   kubectl -n kube-system delete daemonset aws-node
