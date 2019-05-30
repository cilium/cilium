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
<https://github.com/weaveworks/eksctl>`_ for details on how to set credentials,
change region, VPC, cluster size, etc.

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
       
Prepare the nodes for Cilium
============================

Deploy the following DaemonSet to prepare all EKS nodes for Cilium:

   .. code:: bash

       kubectl -n kube-system apply -f \ |SCM_WEB|\/examples/kubernetes/node-init/eks-node-init.yaml

This will mount the BPF filesystem and ensures that the filesystem is
automatically mounted when the node is rebooted. Due to being a DaemonSet, any
new node added to the cluster will automatically get initialized as well.

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
    aws-node-vgc7n                          1/1     Running             0          2m55s
    aws-node-x6sjm                          1/1     Running             0          3m35s
    cilium-cvp8q                            0/1     Init:0/1            0          53s
    cilium-etcd-operator-6d9975f5df-2vflw   0/1     ContainerCreating   0          54s
    cilium-operator-788c55554-gkpbf         0/1     ContainerCreating   0          54s
    cilium-tdzcx                            0/1     Init:0/1            0          53s
    coredns-77b578f78d-km6r4                1/1     Running             0          11m
    coredns-77b578f78d-qr6gq                1/1     Running             0          11m
    kube-proxy-l47rx                        1/1     Running             0          6m28s
    kube-proxy-zj6v5                        1/1     Running             0          6m28s

It may take a couple of minutes for the etcd-operator to bring up the necessary
number of etcd pods to achieve quorum. Once it reaches quorum, all components
should be healthy and ready:

.. parsed-literal::

   kubectl -n=kube-system get pods
   NAME                                    READY   STATUS    RESTARTS   AGE
   aws-node-vgc7n                          1/1     Running   0          2m
   aws-node-x6sjm                          1/1     Running   0          3m
   cilium-cvp8q                            1/1     Running   0          42s
   cilium-etcd-operator-6d9975f5df-2vflw   1/1     Running   0          43s
   cilium-etcd-p2ggsb22nc                  1/1     Running   0          28s
   cilium-operator-788c55554-gkpbf         1/1     Running   2          43s
   cilium-tdzcx                            1/1     Running   0          42s
   coredns-77b578f78d-2khwp                1/1     Running   0          13s
   coredns-77b578f78d-bs6rp                1/1     Running   0          13s
   etcd-operator-7b9768bc99-294wf          1/1     Running   0          37s
   kube-proxy-l47rx                        1/1     Running   0          6m
   kube-proxy-zj6v5                        1/1     Running   0          6m
