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


**Requirements:**

* After installing Cilium, create a `EKS Managed Nodegroup <https://eksctl.io/usage/eks-managed-nodes>`_. 
  

  * Below is an example on how to use `ClusterConfig <https://eksctl.io/usage/creating-and-managing-clusters/#using-config-files>`_
    file to create a node group:  
  
    .. code-block:: none

        cat <<EOF >node-group.yaml
        apiVersion: eksctl.io/v1alpha5
        kind: ClusterConfig

        metadata:
          name: cluster-1
          region: eu-west-1
          version: '1.30'
        
        managedNodeGroups:
          - name: ng-1
            desiredCapacity: 2
            privateNetworking: true
        EOF
        eksctl create nodegroup -f ./node-group.yaml
    
       Ensure cluster name and region matches the values in the ClusterConfig used to create the cluster. 

**Limitations:**

* The AWS ENI integration of Cilium is currently only enabled for IPv4. If you
  want to use IPv6, use a datapath/IPAM mode other than ENI.
