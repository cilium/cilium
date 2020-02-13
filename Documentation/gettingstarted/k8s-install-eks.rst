.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

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
as `environment variables <https://docs.aws.amazon.com/cli/latest/userguide/cli-environment.html>`_ .

Next, install `eksctl <https://github.com/weaveworks/eksctl>`_ :

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

Create the cluster
------------------

Create an EKS cluster with ``eksctl`` see the `eksctl Documentation
<https://github.com/weaveworks/eksctl>`_ for details on how to set credentials,
change region, VPC, cluster size, etc.

   .. code:: bash

     eksctl create cluster -n test-cluster -N 0

You should see something like this:

   .. code:: bash

	[ℹ]  using region us-west-2
	[ℹ]  setting availability zones to [us-west-2b us-west-2a us-west-2c]
	[...]
	[✔]  EKS cluster "test-cluster" in "us-west-2" region is ready

Disable the aws-node DaemonSet (EKS only)
=========================================

If you are running an EKS cluster, disable the ``aws-node`` DaemonSet so it
does not interfere with the ENIs managed by Cilium:

.. code:: bash

   kubectl -n kube-system set image daemonset/aws-node aws-node=docker.io/spaster/alpine-sleep

Prepare & Deploy Cilium
=======================

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set global.eni=true \\
     --set global.egressMasqueradeInterfaces=eth0 \\
     --set global.tunnel=disabled \\
     --set global.nodeinit.enabled=true

.. include:: aws-scale-up-cluster.rst
.. include:: k8s-install-validate.rst
.. include:: hubble-install.rst
.. include:: getting-started-next-steps.rst

