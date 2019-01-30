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

Install eksctl
--------------

.. tabs::
  .. group-tab:: Linux

    .. parsed-literal::

     curl --silent --location "https://github.com/weaveworks/eksctl/releases/download/latest_release/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
     sudo mv /tmp/eksctl /usr/local/bin

  .. group-tab:: MacOS

    .. parsed-literal::

     brew install weaveworks/tap/eksctl

Create the cluster
------------------

Create an EKS cluster with ``eksctl`` see the `eksctl Documentation
<https://github.com/weaveworks/eksctl>`_ for details on how to change region,
VPC, cluster size, ...

   .. code:: bash

     eksctl create cluster

You should see something like this:

   .. code:: bash

	[ℹ]  using region us-west-2
	[ℹ]  setting availability zones to [us-west-2b us-west-2a us-west-2c]
	[ℹ]  subnets for us-west-2b - public:192.168.0.0/19 private:192.168.96.0/19
	[ℹ]  subnets for us-west-2a - public:192.168.32.0/19 private:192.168.128.0/19
	[ℹ]  subnets for us-west-2c - public:192.168.64.0/19 private:192.168.160.0/19
	[ℹ]  nodegroup "ng-1e83ec43" will use "ami-0a2abab4107669c1b" [AmazonLinux2/1.11]
	[ℹ]  creating EKS cluster "ridiculous-gopher-1548608219" in "us-west-2" region
	[ℹ]  will create 2 separate CloudFormation stacks for cluster itself and the initial nodegroup
	[ℹ]  if you encounter any issues, check CloudFormation console or try 'eksctl utils describe-stacks --region=us-west-2 --name=ridiculous-gopher-1548608219'
	[ℹ]  creating cluster stack "eksctl-ridiculous-gopher-1548608219-cluster"
	[ℹ]  creating nodegroup stack "eksctl-ridiculous-gopher-1548608219-nodegroup-ng-1e83ec43"
	[✔]  all EKS cluster resource for "ridiculous-gopher-1548608219" had been created
	[✔]  saved kubeconfig as "/Users/tgraf/.kube/config"
	[ℹ]  nodegroup "ng-1e83ec43" has 0 node(s)
	[ℹ]  waiting for at least 2 node(s) to become ready in "ng-1e83ec43"
	[ℹ]  nodegroup "ng-1e83ec43" has 2 node(s)
	[ℹ]  node "ip-192-168-4-64.us-west-2.compute.internal" is ready
	[ℹ]  node "ip-192-168-42-60.us-west-2.compute.internal" is ready
	[ℹ]  kubectl command should work with "/Users/tgraf/.kube/config", try 'kubectl get nodes'
	[✔]  EKS cluster "ridiculous-gopher-1548608219" in "us-west-2" region is ready


Disable SNAT in aws-node agent
==============================

Disable the SNAT behavior of the aws-node DaemonSet which causes all traffic
leaving a node to be automatically be masqueraded.

   .. code:: bash

       kubectl -n kube-system set env ds aws-node AWS_VPC_K8S_CNI_EXTERNALSNAT=true
       
.. include:: k8s-install-etcd-operator-steps.rst

.. note::

   You may notice that the ``kube-dns-*`` pods get restarted. The
   ``cilium-operator`` will automatically restart CoreDNS if the pods are not
   managed by the Cilium CNI plugin.

Validate the Installation
=========================

You can monitor as Cilium and all required components are being installed:

.. parsed-literal::

    kubectl -n kube-system get pods --watch
    NAME                                    READY   STATUS              RESTARTS   AGE
    cilium-etcd-operator-6ffbd46df9-pn6cf   1/1     Running             0          7s
    cilium-operator-cb4578bc5-q52qk         0/1     Pending             0          8s
    cilium-s8w5m                            0/1     PodInitializing     0          7s
    coredns-86c58d9df4-4g7dd                0/1     ContainerCreating   0          8m57s
    coredns-86c58d9df4-4l6b2                0/1     ContainerCreating   0          8m57s

It may take a couple of minutes for the etcd-operator to bring up the necessary
number of etcd pods to achieve quorum. Once it reaches quorum, all components
should be healthy and ready:
