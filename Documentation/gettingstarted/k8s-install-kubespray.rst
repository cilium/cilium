.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _k8s_install_kubespray:

****************************
Installation using Kubespray
****************************

The guide is to use Kubespray for creating an AWS Kubernetes cluster running 
Cilium as the CNI. The guide uses:

  - Kubespray v2.6.0
  - Latest `Cilium released version <https://github.com/cilium/cilium/releases>`__ (instructions for using the version are mentioned below)

Please consult `Kubespray Prerequisites <https://github.com/kubernetes-incubator/kubespray#requirements>`__ and Cilium :ref:`admin_system_reqs`. 


Installing Kubespray
====================

.. code:: bash

  $ git clone --branch v2.6.0 https://github.com/kubernetes-incubator/kubespray 

Install dependencies from ``requirements.txt``

.. code:: bash

  $ cd kubespray
  $ sudo pip install -r requirements.txt


Infrastructure Provisioning
===========================

We will use Terraform for provisioning AWS infrastructure.

-------------------------
Configure AWS credentials
-------------------------

Export the variables for your AWS credentials 

.. code:: bash

  export AWS_ACCESS_KEY_ID="www"
  export AWS_SECRET_ACCESS_KEY ="xxx"
  export AWS_SSH_KEY_NAME="yyy"
  export AWS_DEFAULT_REGION="zzz"

-----------------------------
Configure Terraform Variables
-----------------------------

We will start by specifying the infrastructure needed for the Kubernetes cluster.

.. code:: bash

  $ cd contrib/terraform/aws
  $ cp contrib/terraform/aws/terraform.tfvars.example terraform.tfvars`

Open the file and change any defaults particularly, the number of master, etcd, and worker nodes. 
You can change the master and etcd number to 1 for deployments that don't need high availability.
By default, this tutorial will create:

  - VPC with 2 public and private subnets
  - Bastion Hosts and NAT Gateways in the Public Subnet
  - Three of each (masters, etcd, and worker nodes) in the Private Subnet
  - AWS ELB in the Public Subnet for accessing the Kubernetes API from
    the internet
  - Terraform scripts using ``CoreOS`` as base image.

Example ``terraform.tfvars`` file:

.. code:: bash

  #Global Vars
  aws_cluster_name = "kubespray"

  #VPC Vars
  aws_vpc_cidr_block = "XXX.XXX.192.0/18"
  aws_cidr_subnets_private = ["XXX.XXX.192.0/20","XXX.XXX.208.0/20"]
  aws_cidr_subnets_public = ["XXX.XXX.224.0/20","XXX.XXX.240.0/20"]

  #Bastion Host
  aws_bastion_size = "t2.medium"


  #Kubernetes Cluster

  aws_kube_master_num = 3
  aws_kube_master_size = "t2.medium"

  aws_etcd_num = 3
  aws_etcd_size = "t2.medium"

  aws_kube_worker_num = 3
  aws_kube_worker_size = "t2.medium"

  #Settings AWS ELB

  aws_elb_api_port = 6443
  k8s_secure_api_port = 6443
  kube_insecure_apiserver_address = "0.0.0.0"


-----------------------
Apply the configuration
-----------------------

``terraform init`` to initialize the following modules

  - ``module.aws-vpc``
  - ``module.aws-elb``
  - ``module.aws-iam``

.. code:: bash

  $ terraform init

Once initialized , execute:

.. code:: bash

  $ terraform plan -out=aws_kubespray_plan

This will generate a file, ``aws_kubespray_plan``, depicting an execution
plan of the infrastructure that will be created on AWS. To apply, execute:

.. code:: bash

  $ terraform init
  $ terraform apply "aws_kubespray_plan"

Terraform automatically creates an Ansible Inventory file at ``inventory/hosts``.

Installing Kubernetes cluster with Cilium as CNI
================================================

Kubespray uses Ansible as its substrate for provisioning and orchestration. Once the infrastructure is created, you can run the Ansible playbook to install Kubernetes and all the required dependencies. Execute the below command in the kubespray clone repo, providing the correct path of the AWS EC2 ssh private key in ``ansible_ssh_private_key_file=<path to EC2 SSH private key file>``

We recommend using the `latest released Cilium version <https://github.com/cilium/cilium/releases>`__ by editing ``roles/download/defaults/main.yml``. Open the file, search for ``cilium_version``, and replace the version with the latest released. As an example, the updated version entry will look like: ``cilium_version: "v1.2.0"``.


.. code:: bash

  $ ansible-playbook -i ./inventory/hosts ./cluster.yml -e ansible_user=core -e bootstrap_os=coreos -e kube_network_plugin=cilium -b --become-user=root --flush-cache  -e ansible_ssh_private_key_file=<path to EC2 SSH private key file>


Validate Cluster
================

To check if cluster is created successfully, ssh into the bastion host with the user ``core``. 

.. code:: bash

  # Get information about the basiton host 
  $ cat ssh-bastion.conf    
  $ ssh -i ~/path/to/ec2-key-file.pem core@public_ip_of_bastion_host 

Execute the commands below from the bastion host. If ``kubectl`` isn't installed on the bastion host, you can login to the master node to test the below commands. You may need to copy the private key to the bastion host to access the master node.

.. code:: bash

  $ kubectl get nodes
  $ kubectl get pods -n kube-system

You should see that nodes are in ``Ready`` state and Cilium pods are in ``Running`` state

.. include:: k8s-install-connectivity-test.rst

Delete Cluster
==============

.. code:: bash

  $ cd contrib/terraform/aws
  $ terraform destroy

