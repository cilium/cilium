To create a cluster with the configuration defined above, pass the
``kind-config.yaml`` you created with the ``--config`` flag of kind.

.. code:: bash

    kind create cluster --config=kind-config.yaml

After a couple of seconds or minutes, a 4 nodes cluster should be created.

A new ``kubectl`` context (``kind-kind``) should be added to ``KUBECONFIG`` or, if unset,
to ``${HOME}/.kube/config``:

.. code:: bash

    kubectl cluster-info --context kind-kind

.. note::
   The cluster nodes will remain in state ``NotReady`` until Cilium is deployed.
   This behavior is expected.
