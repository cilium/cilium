.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_alibabacloud_eni:

*************************************************
Setting Up Cilium in AlibabaCloud ENI Mode (beta)
*************************************************

.. include:: ../beta.rst

.. note::

   The AlibabaCloud ENI integration is still subject to some limitations. See
   :ref:`alibabacloud_eni_limitations` for details.

Create a Cluster on AlibabaCloud
================================

Setup a Kubernetes on AlibabaCloud. You can use any method you prefer.
The quickest way is to create an ACK (Alibaba Cloud Container Service for
Kubernetes) cluster and to replace the CNI plugin with Cilium.
For more details on how to set up an ACK cluster please follow
the `official documentation <https://www.alibabacloud.com/help/doc-detail/86745.htm>`_.


Disable ACK CNI (ACK Only)
==========================

If you are running an ACK cluster, you should delete the ACK CNI.

.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Cilium will manage ENIs instead of the ACK CNI, so any running DaemonSet from
the list below has to be deleted to prevent conflicts.

- ``kube-flannel-ds``
- ``terway``
- ``terway-eni``
- ``terway-eniip``

.. note::

    If you are using ACK with Flannel (DaemonSet ``kube-flannel-ds``),
    the Cloud Controller Manager (CCM) will create route (Pod CIDR) in VPC.
    If your cluster is an Managed Kubernetes you cannot disable this behavior.
    Please consider creating a new cluster.

.. code-block:: shell-session

   kubectl -n kube-system delete daemonset <terway>

The next step is to remove CRD below created by ``terway*`` CNI

.. code-block:: shell-session

    kubectl delete crd \
        ciliumclusterwidenetworkpolicies.cilium.io \
        ciliumendpoints.cilium.io \
        ciliumidentities.cilium.io \
        ciliumnetworkpolicies.cilium.io \
        ciliumnodes.cilium.io \
        bgpconfigurations.crd.projectcalico.org \
        clusterinformations.crd.projectcalico.org \
        felixconfigurations.crd.projectcalico.org \
        globalnetworkpolicies.crd.projectcalico.org \
        globalnetworksets.crd.projectcalico.org \
        hostendpoints.crd.projectcalico.org \
        ippools.crd.projectcalico.org \
        networkpolicies.crd.projectcalico.org


Create AlibabaCloud Secrets
===========================

Before installing Cilium, a new Kubernetes Secret with the AlibabaCloud Tokens needs to
be added to your Kubernetes cluster. This Secret will allow Cilium to gather
information from the AlibabaCloud API which is needed to implement ToGroups policies.

AlibabaCloud Access Keys
------------------------

To create a new access token the `following guide can be used
<https://www.alibabacloud.com/help/doc-detail/93691.htm>`_.
These keys need to have certain `RAM Permissions
<https://ram.console.aliyun.com/overview>`_:

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
            "ecs:DescribeInstances"
          ],
          "Resource": [
            "*"
          ],
          "Effect": "Allow"
        },
        {
          "Action": [
            "vpc:DescribeVSwitches",
            "vpc:ListTagResources"
          ],
          "Resource": [
            "*"
          ],
          "Effect": "Allow"
        }
      ]
    }


As soon as you have the access tokens, the following secret needs to be added,
with each empty string replaced by the associated value as a base64-encoded string:

.. code-block:: yaml
    :name: cilium-secret.yaml

    apiVersion: v1
    kind: Secret
    metadata:
      name: cilium-alibabacloud
      namespace: kube-system
    type: Opaque
    data:
      ALIBABA_CLOUD_ACCESS_KEY_ID: ""
      ALIBABA_CLOUD_ACCESS_KEY_SECRET: ""


The base64 command line utility can be used to generate each value, for example:

.. code-block:: shell-session

    $ echo -n "access_key" | base64
    YWNjZXNzX2tleQ==

This secret stores the AlibabaCloud credentials, which will be used to
connect to the AlibabaCloud API.

.. code-block:: shell-session

    $ kubectl create -f cilium-secret.yaml


Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set alibabacloud.enabled=true \\
     --set ipam.mode=alibabacloud \\
     --set enableIPv4Masquerade=false \\
     --set tunnel=disabled \\
     --set nodeinit.enabled=true

.. note::

   You must ensure that the security groups associated with the ENIs (``eth1``,
   ``eth2``, ...) allow for egress traffic to go outside of the VPC. By default,
   the security groups for pod ENIs are derived from the primary ENI
   (``eth0``).

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst

.. _alibabacloud_eni_limitations:

Limitations
===========

* The Alibaba ENI integration of Cilium is currently only enabled for IPv4.
* Only work with instance support ENI, refer to `Instance families
  <https://www.alibabacloud.com/help/doc-detail/25378.htm>`_.
