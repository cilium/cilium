Cilium will manage ENIs instead of VPC CNI, so the ``aws-node`` DaemonSet
has to be deleted to prevent conflict behavior.

.. note::

   Once ``aws-node`` DaemonSet is deleted, EKS will not try to restore it.

.. code:: bash

   kubectl -n kube-system delete daemonset aws-node
