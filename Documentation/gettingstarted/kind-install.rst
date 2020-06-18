Install Dependencies
====================

1. Install ``docker`` stable as described in
   `Install Docker Engine <https://docs.docker.com/engine/install/>`_

2. Install ``kubectl`` version >= v1.14.0 as described in the
   `Kubernetes Docs <https://kubernetes.io/docs/tasks/tools/install-kubectl/>`_

3. Install ``helm`` >= v3.0.3 per Helm documentation:
   `Installing Helm <https://helm.sh/docs/intro/install/>`_

4. Install ``kind`` >= v0.7.0 per kind documentation:
   `Installation and Usage <https://kind.sigs.k8s.io/#installation-and-usage>`_

Kind Configuration
==================

Kind does not use flags for configuration. Instead, it uses YAML configuration
that is very similar to Kubernetes.

Create a :download:`kind-config.yaml <./kind-config.yaml>` file based on the
following template. The template will create 3 nodes + 1 apiserver cluster with
the latest version of Kubernetes from when the kind release was created.

.. literalinclude:: kind-config.yaml
   :language: yaml

To change the version of Kubernetes being run,  ``image`` has to be defined for
each node. See the
`Node Configration <https://kind.sigs.k8s.io/docs/user/configuration/#nodes>`_
documentation.

Start Kind
==========

Pass the ``kind-config.yaml`` you created with the ``--config`` flag of kind.

.. code:: bash

    kind create cluster --config=kind-config.yaml

This will add a ``kind-kind`` context to ``KUBECONFIG`` or if unset,
``${HOME}/.kube/config``

.. code:: bash

    kubectl cluster-info --context kind-kind
