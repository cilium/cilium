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

   To chain Cilium on top of the AWS CNI, see :ref:`chaining_aws_cni`.

   You can also bring up Cilium in a Single-Region, Multi-Region, or Multi-AZ environment for EKS.

**Limitations:**

* The AWS ENI integration of Cilium is currently only enabled for IPv4. If you
  want to use IPv6, use a datapath/IPAM mode other than ENI.


