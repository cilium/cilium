.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

*******
AWS-CNI
*******

This guide explains how to set up Cilium in combination with aws-cni. In this
hybrid mode, the aws-cni plugin is responsible for setting up the virtual
network devices as well as address allocation (IPAM) via ENI. After the initial
networking is setup, the Cilium CNI plugin is called attach BPF programs to the
network devices set up by aws-cni to enforce network policies, perform
load-balancing, and encryption.

.. image:: aws-cni-architecture.png


Setup Cluster on AWS
====================

Follow the instructions in the :ref:`k8s_install_eks` guide to set up an EKS
cluster or use any other method of your preference to set up a Kubernetes
cluster.

Ensure that the `aws-vpc-cni-k8s <https://github.com/aws/amazon-vpc-cni-k8s>`_
plugin is installed. If you have set up an EKS cluster, this is automatically
done.

Prepare Cilium to use AWS-CNI chaining
======================================

Download the Cilium deployment yaml:

.. tabs::
  .. group-tab:: K8s 1.14

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.14/cilium.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.13/cilium.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.12/cilium.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      curl -sLO \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml

Edit ``cilium.yaml and add the following configuration to the ConfigMap:

.. code:: bash

      cni-chaining-mode: aws-cni
      masquerade: "false"
      tunnel: disabled

This will enable chaining with the aws-cni plugin. It will also disable
tunneling. Tunneling is not required as ENI IP addresses can be directly routed
in your VPC. You can also disable masquerading for the same reason.

Validate your Security Groups
=============================

Validate your AWS security groups rules and ensure that ENI IP addresses as
allocated and used by the aws-cni plugin are allowed. See the documentation of
the `aws-vpc-cni-k8s <https://github.com/aws/amazon-vpc-cni-k8s>`_ plugin for
more details.

Deploy Cilium
=============

.. code:: bash

       kubectl apply -f cilium.yaml

As Cilium is deployed as a DaemonSet, it will write a new CNI configuration
``05-cilium.conflist`` which will take precedence over the standard
``10-aws.conflist``. Any new pod scheduled, will use the chaining configuration
which will not also invoke Cilium.

Restart existing pods
=====================

The new CNI chaining configuration will *not* apply to any pod that is already
running the cluster. Existing pods will be reachable and Cilium will
load-balance to them but policy enforcement will not apply to them and
load-balancing is not performed for traffic originating from existing pods.
You must restart these pods in order to invoke the
chaining configuration on them.

Validate the Setup
==================

Start some pods, and then run ``kubectl get cep`` in the namespace of the pods.
You should see an entry for each pod in ``ready`` state with an ENI IP
addresses assigned to each pod:

.. code:: bash

        NAME                     ENDPOINT ID   IDENTITY ID   INGRESS ENFORCEMENT   EGRESS ENFORCEMENT   ENDPOINT STATE   IPV4             IPV6
        echo-775d85cfd4-7qrd4    1561          31650         false                 false                ready            192.168.61.190
        echo-775d85cfd4-9rvfd    424           31650         false                 false                ready            192.168.43.185
        echo-775d85cfd4-d9nfq    2197          31650         false                 false                ready            192.168.84.131
        echo-775d85cfd4-h8qrv    352           31650         false                 false                ready            192.168.78.253
        echo-775d85cfd4-lkq5g    1308          31650         false                 false                ready            192.168.69.202
        probe-67cdb8c986-hpn7b   2838          13243         false                 false                ready            192.168.90.115
        probe-67cdb8c986-mrfgf   2879          13243         false                 false                ready            192.168.35.144
        probe-67cdb8c986-sj4j7   2673          13243         false                 false                ready            192.168.57.56
        probe-67cdb8c986-td8qb   553           13243         false                 false                ready            192.168.67.25
        probe-67cdb8c986-wqqzj   789           13243         false                 false                ready            192.168.52.109


