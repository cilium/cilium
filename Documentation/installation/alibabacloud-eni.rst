**Alibaba Cloud ENI prerequisites:**

.. include:: /beta.rst

Alibaba Cloud ENI IPAM supports IPv4 and requires ECS instances that support
ENIs. Check the ENI and private IP limits of the selected instance type and the
available addresses in each vSwitch before sizing node pools. See
:ref:`ipam_alibabacloud` for the allocation architecture and configuration.

The operator must run on ECS with access to the instance metadata service and
the ECS and VPC API endpoints. Supply AccessKey credentials through the
Kubernetes Secret below.

**RAM permissions:**

Grant the operator's identity the following RAM permissions to discover cloud
resources and manage ENIs and private IP addresses:

.. code-block:: json

    {
      "Version": "1",
      "Statement": [{
          "Action": [
            "ecs:CreateNetworkInterface",
            "ecs:DescribeNetworkInterfaces",
            "ecs:AttachNetworkInterface",
            "ecs:DetachNetworkInterface",
            "ecs:DeleteNetworkInterface",
            "ecs:DescribeInstanceAttribute",
            "ecs:DescribeInstanceTypes",
            "ecs:AssignPrivateIpAddresses",
            "ecs:UnassignPrivateIpAddresses",
            "ecs:DescribeInstances",
            "ecs:DescribeSecurityGroups",
            "ecs:ListTagResources"
          ],
          "Resource": [
            "*"
          ],
          "Effect": "Allow"
        },
        {
          "Action": [
            "vpc:DescribeVSwitches",
            "vpc:ListTagResources",
            "vpc:DescribeVpcs"
          ],
          "Resource": [
            "*"
          ],
          "Effect": "Allow"
        }
      ]
    }


**AccessKey credentials:**

Follow the `Alibaba Cloud AccessKey guide
<https://www.alibabacloud.com/help/doc-detail/93691.htm>`_ to create AccessKeys.
Save the following as ``cilium-secret.yaml``, replacing the placeholders with
your AccessKey values:

.. code-block:: yaml

    apiVersion: v1
    kind: Secret
    metadata:
      name: cilium-alibabacloud
      namespace: kube-system
    type: Opaque
    stringData:
      ALIBABA_CLOUD_ACCESS_KEY_ID: "<access-key-id>"
      ALIBABA_CLOUD_ACCESS_KEY_SECRET: "<access-key-secret>"


.. code-block:: shell-session

    $ kubectl create -f cilium-secret.yaml

**Install Cilium:**

Install Cilium release via Helm:

.. cilium-helm-install::
   :namespace: kube-system
   :set: alibabacloud.enabled=true
         ipam.mode=alibabacloud
         enableIPv4Masquerade=false
         routingMode=native

.. note::

   With IPv4 masquerading disabled, pod traffic retains its ENI source IP.
   Configure VPC routing and, when required, NAT for access outside the VPC.

   Pod ENIs inherit the primary ENI security groups by default. Allow the
   required pod traffic in those groups.
