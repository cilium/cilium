.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_eks:

***********************
Installation on AWS EKS
***********************

Create an EKS Cluster
=====================

The first step is to create an EKS cluster. This guide will use `eksctl
<https://github.com/weaveworks/eksctl>`_ but you can also follow the `Getting
Started with Amazon EKS
<https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html>`_ guide.

Prerequisites
-------------

Ensure your AWS credentials are located in ``~/.aws/credentials`` or are stored
as `environment variables <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html>`_ .

Next, install `eksctl`_ :

.. tabs::
  .. group-tab:: Linux

    .. parsed-literal::

     curl --silent --location "https://github.com/weaveworks/eksctl/releases/download/latest_release/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
     sudo mv /tmp/eksctl /usr/local/bin

  .. group-tab:: MacOS

    .. parsed-literal::

     brew install weaveworks/tap/eksctl

Ensure that aws-iam-authenticator is installed and in the executable path:

.. parsed-literal::

  which aws-iam-authenticator

If not, install it based on the `AWS IAM authenticator documentation
<https://docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html>`_ .

.. _eksctl: https://github.com/weaveworks/eksctl

Create the cluster
------------------

Create an EKS cluster with ``eksctl`` see the `eksctl Documentation`_ for
details on how to set credentials, change region, VPC, cluster size, etc.

   .. code:: bash

     eksctl create cluster --name test-cluster --without-nodegroup

You should see something like this:

   .. code:: bash

	[ℹ]  using region us-west-2
	[ℹ]  setting availability zones to [us-west-2b us-west-2a us-west-2c]
	[...]
	[✔]  EKS cluster "test-cluster" in "us-west-2" region is ready

.. _eksctl Documentation: eksctl_

Delete VPC CNI (``aws-node`` DaemonSet)
=======================================

.. include:: k8s-install-remove-aws-node.rst

Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set eni=true \\
     --set ipam.mode=eni \\
     --set egressMasqueradeInterfaces=eth0 \\
     --set tunnel=disabled \\
     --set nodeinit.enabled=true

.. note::

   This helm command sets ``eni=true`` and ``tunnel=disabled``,
   meaning that Cilium will allocate a fully-routable AWS ENI IP address for each pod,
   similar to the behavior of the
   `Amazon VPC CNI plugin <https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html>`_.

   Cilium can alternatively run in EKS using an overlay mode that gives pods non-VPC-routable IPs.
   This allows running more pods per Kubernetes worker node than the ENI limit, but means
   that pod connectivity to resources outside the cluster (e.g., VMs in the VPC or AWS managed
   services) is masqueraded (i.e., SNAT) by Cilium to use the VPC IP address of the Kubernetes worker node.
   Excluding the lines for ``eni=true`` and ``tunnel=disabled`` from the
   helm command will configure Cilium to use overlay routing mode (which is the helm default).

.. include:: aws-create-nodegroup.rst
.. include:: k8s-install-validate.rst
.. include:: namespace-kube-system.rst
.. include:: hubble-enable.rst
