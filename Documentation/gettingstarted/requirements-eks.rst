To install Cilium on `Amazon Elastic Kubernetes Service (EKS) <https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html>`_,
perform the following steps:

**Default Configuration:**

===================== =================== ==============
Datapath              IPAM                Datastore
===================== =================== ==============
Direct Routing (ENI)  AWS ENI             Kubernetes CRD
===================== =================== ==============

For more information on AWS ENI mode, see :ref:`ipam_eni`.

.. tip::

   If you want to chain Cilium on top of the AWS CNI, refer to the guide
   :ref:`chaining_aws_cni`.

**Requirements:**

* It is recommended to create an EKS cluster without any nodes, install
  Cilium, and then scale up the number of nodes with Cilium already deployed.

**Limitations:**

* The AWS ENI integration of Cilium is currently only enabled for IPv4. If you
  want to use IPv6, use a datapath/IPAM mode other than ENI.
