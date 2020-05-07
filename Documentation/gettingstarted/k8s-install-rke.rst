.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_rke:

********************************************
Installation using Rancher Kubernetes Engine
********************************************

This guide walks you through integrating Cilium CNI with Kubernetes clusters
deployed using Rancher Kubernetes Engine (RKE). This guide uses:

  - Rancher Kubernetes Engine v1.0.8
  - `Helm`_ Version 3
  - Hosts (1 or more) Running a supported Linux Operating System
  - `Docker`_

Please consult `RKE Requirements`_ and Cilium :ref:`admin_system_reqs`.

.. _RKE Requirements: https://rancher.com/docs/rke/latest/en/os/
.. _Docker: https://docker.io
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

Prepare your Linux Hosts
------------------------

Prepare your hosts with a supported operating system and Docker runtime. This
is outside the scope of this guide.

Prepare a RKE Configuration
---------------------------

Once your nodes are running and have been configured with the docker runtime,
the next step is to generate a `RKE Configuration File <https://rancher.com/docs/rke/latest/en/installation/#creating-the-cluster-configuration-file>`_

Create a new cluster.yml file using prompts:

.. code:: bash

  $ rke config --name cluster.yml

You will need to provide IP Address and SSH connection information along with
any SSH keys used to access the hosts.

When specifying the Network Provider Type enter "none" - note this option is
not listed in the prompt but is supported and documented in the
`official RKE documentation <https://rancher.com/docs/rke/latest/en/config-options/add-ons/network-plugins/custom-network-plugin-example/>`_.
Rather than provide an inline configuration for the network provider, we will
install it using Helm once the cluster is running.

Launch the RKE Cluster
----------------------

Once the configuration file is in place, launch the RKE Kubernetes cluster:

.. code:: bash

  $ rke up

If your config uses a filename different than cluster.yml:

.. code:: bash

  $ rke up --config filename.yml

Once the cluster is launched, the installer will create a file in the local
directory named ```kube_config_cluster.yml``` which can be used to access the
Kubernetes API server. If your input file name was different than the default,
your kubeconfig file will be named ```kube_config_filename.yml```.

.. code:: bash

  $ export KUBECONFIG=$PWD/kube_config_cluster.yml
  $ kubectl get nodes

It is expected to see the nodes in a NotReady state prior to installing Cilium.

Installing Cilium
=================

.. include:: k8s-install-download-release.rst
.. include:: k8s-install-restart-pods.rst
.. include:: k8s-install-validate.rst
.. include:: hubble-install.rst
.. include:: getting-started-next-steps.rst

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`
