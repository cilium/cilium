.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _kops_guide:
.. _k8s_install_kops:

***********************
Installation using Kops
***********************

As of ``kops`` 1.9 release, Cilium can be plugged into ``kops``-deployed
clusters as the CNI plugin. This guide provides steps to create a Kubernetes
cluster on AWS using ``kops`` and Cilium as the CNI plugin. Note, the ``kops``
deployment will automate several deployment features in AWS by default,
including AutoScaling, Volumes, VPCs, etc.

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
the ``kops`` user and group:

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


``kops`` requires the creation of a dedicated S3 bucket in order to store the
state and representation of the cluster. You will need to change the bucket
name and provide your unique bucket name (for example a reverse of FQDN added
with short description of the cluster). Also make sure to use the region where
you will be deploying the cluster.

.. code:: bash

        aws s3api create-bucket --bucket prefix-example-com-state-store --region us-west-2 --create-bucket-configuration LocationConstraint=us-west-2
        export KOPS_STATE_STORE=s3://prefix-example-com-state-store

The above steps are sufficient for getting a working cluster installed. Please
consult `kops aws documentation
<https://github.com/kubernetes/kops/blob/master/docs/getting_started/aws.md>`_ for more
detailed setup instructions.

Cilium Prerequisites
====================

* Ensure the :ref:`admin_system_reqs` are met, particularly the Linux kernel
  and key-value store versions.

In this guide, we will use etcd version 3.1.11 and the latest CoreOS stable
image which satisfies the minimum kernel version requirement of Cilium. To get
the latest CoreOS ``ami`` image, you can change the region value to your choice
in the command below.

.. code:: bash

        aws ec2 describe-images --region=us-west-2 --owner=595879546273 --filters "Name=virtualization-type,Values=hvm" "Name=name,Values=CoreOS-stable*" --query 'sort_by(Images,&CreationDate)[-1].{id:ImageLocation}'

.. code:: json

        {
                "id": "595879546273/CoreOS-stable-1745.5.0-hvm"
        }


Creating a Cluster
==================

* Note that you will need to specify the ``--master-zones`` and ``--zones`` for
  creating the master and worker nodes. The number of master zones should be
  * odd (1, 3, ...) for HA. For simplicity, you can just use 1 region.
* The cluster ``NAME`` variable should end with ``k8s.local`` to use the gossip
  protocol. If creating multiple clusters using the same kops user, then make
  the cluster name unique by adding a prefix such as ``com-company-emailid-``.


.. code:: bash

        export NAME=com-company-emailid-cilium.k8s.local
        export KOPS_FEATURE_FLAGS=SpecOverrideFlag
        kops create cluster --state=${KOPS_STATE_STORE} --node-count 3 --node-size t2.medium --master-size t2.medium --topology private --master-zones us-west-2a,us-west-2b,us-west-2c --zones us-west-2a,us-west-2b,us-west-2c --image 595879546273/CoreOS-stable-1745.5.0-hvm --networking cilium --override "cluster.spec.etcdClusters[*].version=3.1.11" --kubernetes-version 1.10.3  --cloud-labels "Team=Dev,Owner=Admin" ${NAME}


You may be prompted to create a ssh public-private key pair.

.. code:: bash

        ssh-keygen


(Please see :ref:`appendix_kops`)

.. include:: k8s-install-connectivity-test.rst

.. _appendix_kops:

Deleting a Cluster
==================

To undo the dependencies and other deployment features in AWS from the ``kops``
cluster creation, use ``kops`` to destroy a cluster *immediately* with the
parameter ``--yes``:

.. code:: bash

        kops delete cluster ${NAME} --yes

Appendix: Details of kops flags used in cluster creation
========================================================

The following section explains all the flags used in create cluster command.

* ``KOPS_FEATURE_FLAGS=SpecOverrideFlag`` : This flag is used to override the etcd version to be used from 2.X[kops default ] to 3.1.x [requirement of cilium]
* ``--state=${KOPS_STATE_STORE}`` : KOPS uses an S3 bucket to store the state of your cluster and representation of your cluster
* ``--node-count 3`` : No. of worker nodes in the kubernetes cluster.
* ``--node-size t2.medium`` : The size of the AWS EC2 instance for worker nodes
* ``--master-size t2.medium`` : The size of the AWS EC2 instance of master nodes
* ``--topology private`` : Cluster will be created with private topology, what that means is all masters/nodes will be launched in a private subnet in the VPC
* ``--master-zones eu-west-1a,eu-west-1b,eu-west-1c`` : The 3 zones ensure the HA of master nodes, each belonging in a different Availability zones.
* ``--zones eu-west-1a,eu-west-1b,eu-west-1c`` : Zones where the worker nodes will be deployed
* ``--image 595879546273/CoreOS-stable-1745.3.1-hvm`` : Image name to be deployed (Cilium requires kernel version 4.8 and above so ensure to use the right OS for workers.)
* ``--networking cilium`` : Networking CNI plugin to be used - cilium
* ``--override "cluster.spec.etcdClusters[*].version=3.1.11"`` : Overrides the etcd version to be used.
* ``--kubernetes-version 1.10.3`` : Kubernetes version that is to be installed. Please note [Kops 1.9 officially supports k8s version 1.9]
* ``--cloud-labels "Team=Dev,Owner=Admin"`` :  Labels for your cluster
* ``${NAME}`` : Name of the cluster. Make sure the name ends with k8s.local for a gossip based cluster
