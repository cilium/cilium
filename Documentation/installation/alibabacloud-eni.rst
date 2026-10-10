**Alibaba Cloud ENI prerequisites:**

.. include:: /beta.rst

Alibaba Cloud ENI IPAM supports IPv4 and requires ECS instances that support
ENIs. Check the ENI and private IP limits of the selected instance type and the
available addresses in each vSwitch before sizing node pools. See
:ref:`ipam_alibabacloud` for the allocation architecture and configuration.

The operator must run on ECS with access to the instance metadata service and
the ECS and VPC API endpoints. Use RRSA (recommended) or configure AccessKey
credentials for the operator as described below.

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


**RRSA credentials (recommended):**

Use RAM Roles for Service Accounts (RRSA) to give the operator temporary
credentials and avoid storing long-lived AccessKeys in Kubernetes. Follow the
`ACK RRSA guide
<https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services>`_
to enable RRSA and create a RAM role using the cluster's OIDC provider. Restrict
the role's trust policy to ``oidc:sub`` equal to
``system:serviceaccount:kube-system:cilium-operator`` and grant it the RAM
permissions above. Adjust the subject if you change the operator's namespace
or ServiceAccount name.

Save the following as ``rrsa-values.yaml``, replacing the role ARN, OIDC
provider ARN, and region with your values:

.. code-block:: yaml

    operator:
      extraEnv:
        - name: ALIBABA_CLOUD_ROLE_ARN
          value: "<role-arn>"
        - name: ALIBABA_CLOUD_OIDC_PROVIDER_ARN
          value: "<oidc-provider-arn>"
        - name: ALIBABA_CLOUD_OIDC_TOKEN_FILE
          value: /var/run/secrets/ack.alibabacloud.com/rrsa-tokens/token
        - name: ALIBABA_CLOUD_STS_REGION
          value: "<region-id>"
        - name: ALIBABA_CLOUD_VPC_ENDPOINT_ENABLED
          value: "true"
      extraVolumes:
        - name: rrsa-oidc-token
          projected:
            sources:
              - serviceAccountToken:
                  audience: sts.aliyuncs.com
                  expirationSeconds: 3600
                  path: token
      extraVolumeMounts:
        - name: rrsa-oidc-token
          mountPath: /var/run/secrets/ack.alibabacloud.com/rrsa-tokens
          readOnly: true

This mounts a rotating token for the operator's existing ServiceAccount,
with the STS audience, and uses the regional STS VPC endpoint. No identity
webhook is required. Skip the AccessKey Secret below;
static AccessKeys take precedence over RRSA in the credential chain.

**AccessKey credentials (alternative):**

If RRSA is unavailable, you can supply static AccessKey credentials through a
Kubernetes Secret. Prefer RRSA to reduce the risk of long-lived credential
exposure.

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

Install Cilium release via Helm. For RRSA, add ``--values rrsa-values.yaml``
to the following command:

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
