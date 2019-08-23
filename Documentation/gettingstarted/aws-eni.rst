.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _k8s_aws_eni:

*********************************
Setting up Cilium in AWS ENI mode
*********************************

.. note::

   The AWS ENI integration is still subject to some limitations. See
   :ref:`eni_limitations` for details.

Create an AWS cluster
=====================

Setup a Kubernetes on AWS. You can use any method you prefer, bu for the
simplicity of this tutorial, we are going to use `eksctl
<https://github.com/weaveworks/eksctl>`_. For more details on how to set up an
EKS cluster using ``eksctl``, see the section :ref:`k8s_install_eks`.

.. code:: bash

   eksctl create cluster -n eni-cluster -N 0

Disable the aws-node DaemonSet (EKS only)
=========================================

If you are running an EKS cluster, disable the ``aws-node`` DaemonSet so it
does not interfere with the ENIs managed by Cilium:

.. code:: bash

   kubectl -n kube-system set image daemonset/aws-node aws-node=docker.io/spaster/alpine-sleep

Prepare & Deploy Cilium
=======================

.. include:: k8s-install-download-release.rst

Generate the required YAML file and deploy it:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.eni=true \
     --set global.egressMasqueradeInterfaces=eth0 \
     --set global.tunnel=disabled \
     --set global.nodeinit.enabled=true \
     > cilium.yaml
   kubectl create -f cilium.yaml

.. note::

   The above options are assuming that masquerading is desired and that the VM
   is connected to the VPC using ``eth0``. It will route all traffic that does
   not stay in the VPC via ``eth0`` and masquerade it.

   If you want to avoid masquerading, set ``global.masquerade=false``. You must
   ensure that the security groups associated with the ENIs (``eth1``,
   ``eth2``, ...) allow for egress traffic to outside of the VPC. By default,
   the security groups for pod ENIs are derived from the primary ENI
   (``eth0``).

Scale up the cluster
====================

.. code:: bash

    eksctl get nodegroup --cluster eni-cluster
    CLUSTER			NODEGROUP	CREATED			MIN SIZE	MAX SIZE	DESIRED CAPACITY	INSTANCE TYPE	IMAGE ID
    test-cluster        	ng-25560078	2019-07-23T06:05:35Z	0		2		0			m5.large	ami-0923e4b35a30a5f53

.. code:: bash

    eksctl scale nodegroup --cluster eni-cluster -n ng-25560078 -N 2
    [ℹ]  scaling nodegroup stack "eksctl-test-cluster-nodegroup-ng-25560078" in cluster eksctl-test-cluster-cluster
    [ℹ]  scaling nodegroup, desired capacity from 0 to 2

.. include:: k8s-install-validate.rst

.. _eni_limitations:

Limitations
===========

* The AWS ENI integration of Cilium is currently only enabled for IPv4.
* When applying L7 policies at egress, the source identity context is lost as
  it is currently not carried in the packet. This means that traffic will look
  like it is coming from outside of the cluster to the receiving pod.
