.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k0s_install:

*****************************
Installation k0s Using k0sctl
*****************************

This guide walks you through installation of Cilium on `k0s <https://k0sproject.io/>`_,
an open source, all-inclusive Kubernetes distribution, 
which is configured with all of the features needed to build a Kubernetes cluster.

Cilium is presently supported on amd64 and arm64 architectures.

Install a Master Node
=====================

Ensure you have the k0sctl binary installed locally.

Setup your VMs:

How to do this is out of the scope of this guide, please refer to your favorite virtualization tool.
After deploying the VMs, export their IP addresses to environment variables (see example below). These will be used in a later step.

.. code-block:: shell-session

   export node1-IP=192.168.2.1 node2-IP=192.168.2.2 node3-IP=192.168.2.3


Prepare the yaml configuration file k0sctl will use:

.. code-block:: shell-session

   # The following command assumes the user has deployed 3 VMs
   # with the default user "k0s" using the default ssh-key (without passphrase)
   k0sctl init --k0s -n "myk0scluster" -u "k0s" -i "~/.ssh/id_rsa" -C "1" "${node1-IP}" "${node2-IP}" "${node3-IP}" > k0s-myk0scluster-config.yaml
   

Next step is editing ``k0s-myk0scluster-config.yaml``::

   # replace 
    ...
      provider: kube-router
    ...
   # with
    ...
      provider: custom
    ...

Finally apply the config file:

.. code-block:: shell-session

   k0sctl apply --config k0s-myk0scluster-config.yaml --no-wait
   
   
.. note::

   If running Cilium in :ref:`kubeproxy-free` mode disable kube-proxy in the k0s config file


   .. code-block:: shell-session

      # edit k0s-myk0scluster-config.yaml

      # replace
      ...
         network:
            kubeProxy:
               disabled: false
      ...
      # with
      ...
         network:
            kubeProxy:
               disabled: true
      ...

Configure Cluster Access
========================

For the Cilium CLI to access the cluster in successive steps you will need to
generate the ``kubeconfig`` file, store it in ``~/.kube/k0s-mycluster.config`` and setting
the ``KUBECONFIG`` environment variable:

.. code-block:: shell-session

    k0sctl kubeconfig --config k0s-myk0scluster-config.yaml > ~/.kube/k0s-mycluster.config
    export KUBECONFIG=~/.kube/k0s-mycluster.config

Install Cilium
==============

.. include:: cli-download.rst

Install Cilium by running:

.. code-block:: shell-session

    cilium install

Validate the Installation
=========================

.. include:: cli-status.rst
.. include:: cli-connectivity-test.rst

.. include:: next-steps.rst
