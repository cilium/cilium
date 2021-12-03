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

The following command creates a Kubernetes cluster with ``eksctl``
using `Amazon Elastic Kubernetes Service
<https://aws.amazon.com/eks/>`_.  See `eksctl Installation
<https://github.com/weaveworks/eksctl>`_ for instructions on how to
install ``eksctl`` and prepare your account.

.. code-block:: shell-session

   export NAME="$(whoami)-$RANDOM"
   cat <<EOF >eks-config.yaml
   apiVersion: eksctl.io/v1alpha5
   kind: ClusterConfig

   metadata:
     name: ${NAME}
     region: eu-west-1

   managedNodeGroups:
   - name: ng-1
     desiredCapacity: 2
     privateNetworking: true
     ## taint nodes so that application pods are
     ## not scheduled until Cilium is deployed.
     taints:
      - key: "node.cilium.io/agent-not-ready"
        value: "true"
        effect: "NoSchedule"
   EOF
   eksctl create cluster -f ./eks-config.yaml

**Limitations:**

* The AWS ENI integration of Cilium is currently only enabled for IPv4. If you
  want to use IPv6, use a datapath/IPAM mode other than ENI.
