.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _kops_guide:
.. _k8s_install_kops:

***********************
Installation using Kops
***********************

As of kops 1.9 release, Cilium can be plugged into kops-deployed
clusters as the CNI plugin. This guide provides steps to create a Kubernetes
cluster on AWS using kops and Cilium as the CNI plugin. Note, the kops
deployment will automate several deployment features in AWS by default,
including AutoScaling, Volumes, VPCs, etc.

Kops offers several out-of-the-box configurations of Cilium including :ref:`kubeproxy-free`,
:ref:`ipam_eni`, and dedicated etcd cluster for Cilium. This guide will just go through a basic setup.


Prerequisites
=============

* `aws cli <https://aws.amazon.com/cli/>`_
* `kubectl <https://kubernetes.io/docs/tasks/tools/install-kubectl>`_
* aws account with permissions:
  * AmazonEC2FullAccess
  * AmazonRoute53FullAccess
  * AmazonS3FullAccess
  * IAMFullAccess
  * AmazonVPCFullAccess


Installing kops
===============

.. tabs::
  .. group-tab:: Linux

    .. parsed-literal::

        curl -LO https://github.com/kubernetes/kops/releases/download/$(curl -s https://api.github.com/repos/kubernetes/kops/releases/latest | grep tag_name | cut -d '"' -f 4)/kops-linux-amd64
        chmod +x kops-linux-amd64
        sudo mv kops-linux-amd64 /usr/local/bin/kops

  .. group-tab:: MacOS

    .. parsed-literal::

        brew update && brew install kops


Setting up IAM Group and User
=============================

Assuming you have all the prerequisites, run the following commands to create
the kops user and group:

.. code:: bash

        # Create IAM group named kops and grant access
        aws iam create-group --group-name kops
        aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess --group-name kops
        aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonRoute53FullAccess --group-name kops
        aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess --group-name kops
        aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/IAMFullAccess --group-name kops
        aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonVPCFullAccess --group-name kops
        aws iam create-user --user-name kops
        aws iam add-user-to-group --user-name kops --group-name kops
        aws iam create-access-key --user-name kops


kops requires the creation of a dedicated S3 bucket in order to store the
state and representation of the cluster. You will need to change the bucket
name and provide your unique bucket name (for example a reverse of FQDN added
with short description of the cluster). Also make sure to use the region where
you will be deploying the cluster.

.. code:: bash

        aws s3api create-bucket --bucket prefix-example-com-state-store --region us-west-2 --create-bucket-configuration LocationConstraint=us-west-2
        export KOPS_STATE_STORE=s3://prefix-example-com-state-store

The above steps are sufficient for getting a working cluster installed. Please
consult `kops aws documentation
<https://kops.sigs.k8s.io/getting_started/install/>`_ for more
detailed setup instructions.


Cilium Prerequisites
====================

* Ensure the :ref:`admin_system_reqs` are met, particularly the Linux kernel
  and key-value store versions.

The default AMI satisfies the minimum kernel version required by Cilium, which is
what we will use in this guide.


Creating a Cluster
==================

* Note that you will need to specify the ``--master-zones`` and ``--zones`` for
  creating the master and worker nodes. The number of master zones should be
  * odd (1, 3, ...) for HA. For simplicity, you can just use 1 region.
* To keep things simple when following this guide, we will use a gossip-based cluster.
  This means you do not have to create a hosted zone upfront.  cluster ``NAME`` variable
  must end with ``k8s.local`` to use the gossip  protocol. If creating multiple clusters
  using the same kops user, then make the cluster name unique by adding a prefix such as 
  ``com-company-emailid-``.


.. code:: bash

        export NAME=com-company-emailid-cilium.k8s.local
        kops create cluster --state=${KOPS_STATE_STORE} --node-count 3 --topology private --master-zones us-west-2a,us-west-2b,us-west-2c --zones us-west-2a,us-west-2b,us-west-2c --networking cilium --cloud-labels "Team=Dev,Owner=Admin" ${NAME} --yes


You may be prompted to create a ssh public-private key pair.

.. code:: bash

        ssh-keygen


(Please see :ref:`appendix_kops`)

.. include:: k8s-install-connectivity-test.rst

.. _appendix_kops:


Deleting a Cluster
==================

To undo the dependencies and other deployment features in AWS from the kops
cluster creation, use kops to destroy a cluster *immediately* with the
parameter ``--yes``:

.. code:: bash

        kops delete cluster ${NAME} --yes


Further reading on using Cilium with Kops
=========================================
* See the `kops networking documentation <https://kops.sigs.k8s.io/networking/cilium/>`_ for more information on the 
  configuration options kops offers.
* See the `kops cluster spec documentation <https://pkg.go.dev/k8s.io/kops/pkg/apis/kops?tab=doc#CiliumNetworkingSpec>`_ for a comprehensive list of all the options


Appendix: Details of kops flags used in cluster creation
========================================================

The following section explains all the flags used in create cluster command.

* ``--state=${KOPS_STATE_STORE}`` : KOPS uses an S3 bucket to store the state of your cluster and representation of your cluster
* ``--node-count 3`` : No. of worker nodes in the kubernetes cluster.
* ``--topology private`` : Cluster will be created with private topology, what that means is all masters/nodes will be launched in a private subnet in the VPC
* ``--master-zones eu-west-1a,eu-west-1b,eu-west-1c`` : The 3 zones ensure the HA of master nodes, each belonging in a different Availability zones.
* ``--zones eu-west-1a,eu-west-1b,eu-west-1c`` : Zones where the worker nodes will be deployed
* ``--networking cilium`` : Networking CNI plugin to be used - cilium. You can also use ``cilium-etcd``, which will use a dedicated etcd cluster as key/value store instead of CRDs.
* ``--cloud-labels "Team=Dev,Owner=Admin"`` :  Labels for your cluster that will be applied to your instances
* ``${NAME}`` : Name of the cluster. Make sure the name ends with k8s.local for a gossip based cluster