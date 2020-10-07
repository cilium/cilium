.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_aws_eni:

*********************************
Setting up Cilium in AWS ENI mode
*********************************

.. note::

   The AWS ENI integration is still subject to some limitations. See
   :ref:`eni_limitations` for details.

Create an AWS cluster
=====================

Setup a Kubernetes on AWS. You can use any method you prefer, but for the
simplicity of this tutorial, we are going to use `eksctl
<https://github.com/weaveworks/eksctl>`_. For more details on how to set up an
EKS cluster using ``eksctl``, see the section :ref:`k8s_install_eks`.

.. code:: bash

   eksctl create cluster --name test-cluster --without-nodegroup

Disable VPC CNI (``aws-node`` DaemonSet) (EKS only)
===================================================

If you are running an EKS cluster, you should delete the ``aws-node`` DaemonSet.

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

   The above options are assuming that masquerading is desired and that the VM
   is connected to the VPC using ``eth0``. It will route all traffic that does
   not stay in the VPC via ``eth0`` and masquerade it.

   If you want to avoid masquerading, set ``masquerade=false``. You must
   ensure that the security groups associated with the ENIs (``eth1``,
   ``eth2``, ...) allow for egress traffic to outside of the VPC. By default,
   the security groups for pod ENIs are derived from the primary ENI
   (``eth0``).

.. include:: aws-create-nodegroup.rst
.. include:: k8s-install-validate.rst
.. include:: namespace-kube-system.rst
.. include:: hubble-enable.rst

.. _eni_limitations:

Limitations
===========

* The AWS ENI integration of Cilium is currently only enabled for IPv4.
* When applying L7 policies at egress, the source identity context is lost as
  it is currently not carried in the packet. This means that traffic will look
  like it is coming from outside of the cluster to the receiving pod.

Troubleshooting
===============

Make sure to disable DHCP on ENIs
---------------------------------

Cilium will use both the primary and secondary IP addresses assigned to ENIs.
Use of the primary IP address optimizes the number of IPs available to pods but
can conflict with a DHCP agent running on the node and assigning the primary IP
of the ENI to the interface of the node. A common scenario where this happens
is if ``NetworkManager`` is running on the node and automatically performing
DHCP on all network interfaces of the VM. Be sure to disable DHCP on any ENIs
that get attached to the node or disable ``NetworkManager`` entirely.
