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

Configure kind
==============

Configuring kind cluster creation is done using a YAML configuration file.
This step is necessary in order to disable the default CNI and replace it with
Cilium.

Create a :download:`kind-config.yaml <./kind-config.yaml>` file based on the
following template. It will create a cluster with 3 worker nodes and 1
control-plane node.

.. literalinclude:: kind-config.yaml
   :language: yaml

By default, the latest version of Kubernetes from when the kind release was
created is used.

To change the version of Kubernetes being run,  ``image`` has to be defined for
each node. See the
`Node Configuration <https://kind.sigs.k8s.io/docs/user/configuration/#nodes>`_
documentation for more information.

.. tip::
    By default, kind uses the following pod and service subnets:

    .. parsed-literal::
        Networking.PodSubnet     = "10.244.0.0/16"
        Networking.ServiceSubnet = "10.96.0.0/12"

    If any of these subnets conflicts with your local network address range,
    update the ``networking`` section of the kind configuration file to specify
    different subnets that do not conflict or you risk having connectivity
    issues when deploying Cilium. For example:

    .. code-block:: yaml

         networking:
           disableDefaultCNI: true
           podSubnet: "10.10.0.0/16"
           serviceSubnet: "10.11.0.0/16"

Create a cluster
================

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
