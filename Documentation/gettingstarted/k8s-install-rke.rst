.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_rke:

********************************************
Installation using Rancher Kubernetes Engine
********************************************

The guide walks you through integrating Cilium CNI with Kubernetes clusters
deployed using Rancher Kubernetes Engine (RKE). The guide uses:

  - Rancher Kubernetes Engine v1.0.8
  - `Helm`_ Version 3

Please consult `RKE Requirements`_ and Cilium :ref:`admin_system_reqs`.

.. _RKE Requirements: https://rancher.com/docs/rke/latest/en/os/
.. _Helm: https://helm.sh

Installing Rancher Kubernetes Engine
====================================

Install the RKE Binary according to the `RKE Installation Guide <https://rancher.com/docs/rke/latest/en/installation/>`_

Alternatively, on macOS the binary can be installed using Homebrew:

.. code:: bash

  $ brew install rke

If you have a previous version of RKE installed, you can update it:


.. code:: bash

  $ brew upgrade rke

Prepare the Kubernetes Cluster
==============================

Prepare your hosts with a supported operating system and Docker runtime. This
is outside the scope of this guide.

Prepare a RKE Configuration
---------------------------

Once your nodes are running and have been configured with the docker runtime,
the next step is to generate a `RKE Configuration File <https://rancher.com/docs/rke/latest/en/installation/#creating-the-cluster-configuration-file>`_

You can create a new cluster.yaml file using prompts:

.. code:: bash

  $ rke config --name cluster.yaml

You can also use the `minimal example <https://rancher.com/docs/rke/latest/en/example-yamls/#minimal-cluster-yaml-example>`_

When specifying the Network Provider Type enter none.

.. code-block:: yaml

  {network: {plugin: none}}


Launch the RKE Cluster
----------------------

Once the configuration file is in place, launch the RKE Kubernetes cluster:

.. code:: bash

  $ rke up

If your config uses a filename different than cluster.yaml:

.. code:: bash

  $ rke up --config <filename>

Once the cluster is launched, the installer will create a file in the local
directory named kube_config_<FILE_NAME>.yml which can be used to access the
Kubernetes API server.

.. code:: bash

  $ export KUBECONFIG=$PWD/kube_config_cluster.yml
  $ kubectl get nodes

Installing Cilium
=================

Cilium installation requires `Helm`_ version 3. You can install Helm according
to the `Helm Installation Guide <https://docs.helm.sh/docs/intro/install/>`_.

Next, add the Cilium helm repository:

.. code:: bash

  $ helm repo add cilium https://helm.cilium.io

Finally, install Cilium as your CNI:

.. tabs::
  .. group-tab:: Helm

    .. code:: bash

     $ helm install --namespace kube-system cilium cilium/cilium

  .. group-tab:: kubectl

    .. code:: bash

      $ helm template --namespace kube-system cilium/cilium > cilium.yaml
      $ kubectl apply -f cilium.yaml

.. include:: k8s-install-validate.rst
.. include:: hubble-install.rst
.. include:: getting-started-next-steps.rst

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`
