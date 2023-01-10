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

* The `EKS Managed Nodegroups <https://eksctl.io/usage/eks-managed-nodes>`_ must
  be properly tainted to ensure applications pods are properly managed by
  Cilium:

  * ``managedNodeGroups`` should be tainted with
    ``node.cilium.io/agent-not-ready=true:NoExecute`` to ensure application
    pods will only be scheduled once Cilium is ready to manage them. However,
    there are other options. Please make sure to read and understand the
    documentation page on :ref:`taint effects and unmanaged pods<taint_effects>`.
  
    Below is an example on how to use `ClusterConfig <https://eksctl.io/usage/creating-and-managing-clusters/#using-config-files>`_
    file to create the cluster:

    .. code-block:: yaml

        apiVersion: eksctl.io/v1alpha5
        kind: ClusterConfig
        ...
        managedNodeGroups:
        - name: ng-1
          ...
          # taint nodes so that application pods are
          # not scheduled/executed until Cilium is deployed.
          # Alternatively, see the note above regarding taint effects.
          taints:
           - key: "node.cilium.io/agent-not-ready"
             value: "true"
             effect: "NoExecute"

**Limitations:**

* The AWS ENI integration of Cilium is currently only enabled for IPv4. If you
  want to use IPv6, use a datapath/IPAM mode other than ENI.
