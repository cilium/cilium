.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_cloud_providers:

**************************
Cloud Provider Deployments
**************************

This page covers cloud-provider-specific guidance for deploying Cilium's
Gateway API support on managed Kubernetes services. Each cloud provider
provisions a cloud-native load balancer for each Gateway automatically, so no
additional L2/IPAM configuration (such as ``CiliumLoadBalancerIPPool``) is
required.

.. _gs_gateway_gke:

GKE
===

Prerequisites
-------------

* A GKE cluster with Cilium installed as the CNI.
  See :doc:`the GKE installation requirements </installation/requirements-gke>`
  for initial setup and the required node taints.
* ``kubeProxyReplacement=true`` — required by the Gateway API controller.
* ``gatewayAPI.enabled=true`` — enables the Cilium Gateway API controller.
* The Gateway API CRDs must be pre-installed (see :ref:`gs_gateway_api` for
  the full prerequisites list).
* Each Gateway creates a **Google Cloud Network Load Balancer (NLB)**
  automatically via the
  `GKE LoadBalancer service integration <https://cloud.google.com/kubernetes-engine/docs/concepts/service-load-balancer>`_;
  no extra IPAM configuration is required. GKE assigns an external IP to the
  NLB.

Installation
------------

.. code-block:: shell-session

    $ cilium install \
        --set kubeProxyReplacement=true \
        --set gatewayAPI.enabled=true \
        --set loadBalancer.l7.backend=envoy \
        --set agentNotReadyTaintKey=ignore-taint.cluster-autoscaler.kubernetes.io/cilium-agent-not-ready

Or via Helm:

.. code-block:: shell-session

    $ helm upgrade cilium cilium/cilium \
        --namespace kube-system \
        --reuse-values \
        --set kubeProxyReplacement=true \
        --set gatewayAPI.enabled=true \
        --set loadBalancer.l7.backend=envoy \
        --set agentNotReadyTaintKey=ignore-taint.cluster-autoscaler.kubernetes.io/cilium-agent-not-ready
    $ kubectl -n kube-system rollout restart deployment/cilium-operator
    $ kubectl -n kube-system rollout restart ds/cilium

Verification
------------

After creating a Gateway resource, inspect the ``ADDRESS`` field to confirm
that GKE has provisioned the external IP:

.. code-block:: shell-session

    $ kubectl get gateway -A
    NAMESPACE   NAME       CLASS    ADDRESS          PROGRAMMED   AGE
    default     my-gw      cilium   203.0.113.42     True         2m

Known Specifics
---------------

* **GKE Autopilot**: `Autopilot <https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview>`_
  restricts host-level access, so :ref:`host network mode <gs_gateway_host_network_mode>`
  is not supported. Use the default LoadBalancer service type instead.
* **Firewall rules**: GKE automatically creates ingress firewall rules for
  the NLB target ports. If you are restricting traffic with custom firewall
  policies, ensure that ports 80 and 443 (or whichever ports your Gateway
  listens on) are permitted from the
  `Google health-check source ranges <https://cloud.google.com/load-balancing/docs/health-check-concepts#ip-ranges>`_:
  ``35.191.0.0/16`` and ``130.211.0.0/22``.
* **Agent-not-ready taint**: GKE sets the
  ``node.cilium.io/agent-not-ready`` taint on new nodes by default. Cilium
  is configured to use
  ``ignore-taint.cluster-autoscaler.kubernetes.io/cilium-agent-not-ready``
  instead, which the GKE autoscaler understands. Set this via
  ``agentNotReadyTaintKey`` as shown above.

.. _gs_gateway_eks:

EKS
===

Prerequisites
-------------

* An EKS cluster with Cilium installed as the CNI.
  See :doc:`the EKS installation requirements </installation/requirements-eks>`
  for initial setup instructions.
* ``kubeProxyReplacement=true`` — required by the Gateway API controller.
* ``gatewayAPI.enabled=true`` — enables the Cilium Gateway API controller.
* The Gateway API CRDs must be pre-installed (see :ref:`gs_gateway_api` for
  the full prerequisites list).
* Each Gateway creates an
  `AWS Network Load Balancer (NLB) <https://docs.aws.amazon.com/eks/latest/userguide/network-load-balancing.html>`_
  via the standard Kubernetes LoadBalancer service mechanism. No extra IPAM
  configuration is required.

Installation
------------

.. code-block:: shell-session

    $ cilium install \
        --set kubeProxyReplacement=true \
        --set gatewayAPI.enabled=true \
        --set loadBalancer.l7.backend=envoy

Or via Helm:

.. code-block:: shell-session

    $ helm upgrade cilium cilium/cilium \
        --namespace kube-system \
        --reuse-values \
        --set kubeProxyReplacement=true \
        --set gatewayAPI.enabled=true \
        --set loadBalancer.l7.backend=envoy
    $ kubectl -n kube-system rollout restart deployment/cilium-operator
    $ kubectl -n kube-system rollout restart ds/cilium

Verification
------------

On EKS, the AWS NLB exposes a DNS hostname rather than an IP address. Expect
the ``ADDRESS`` field to contain an FQDN:

.. code-block:: shell-session

    $ kubectl get gateway -A
    NAMESPACE   NAME     CLASS    ADDRESS                                                                 PROGRAMMED   AGE
    default     my-gw    cilium   a1b2c3d4e5f6g7h8-123456789.us-west-2.elb.amazonaws.com                True         3m

Known Specifics
---------------

* **FQDN address**: Unlike GKE and AKS, the Gateway ``ADDRESS`` field
  contains an AWS DNS hostname, not an IP. When configuring DNS records
  for your services, create a ``CNAME`` record pointing to this hostname.
* **ENI mode and IPAM**: In
  `ENI mode <https://docs.aws.amazon.com/eks/latest/userguide/cni-ipv6.html>`_
  (``--ipam=eni``), only IPv4 is supported. For dual-stack Gateway API
  deployments, use the ``cluster-pool`` IPAM mode instead.
* **Security groups**: Ensure that the worker node security group allows
  inbound traffic on the ports your Gateway listens on (typically 80/443)
  from the NLB and, if applicable, from the health-check subnets.
* **Prefix delegation**: EKS clusters using ENI prefix delegation
  (``eni.awsEnablePrefixDelegation=true``) work normally with Gateway API.
  No special configuration is required.

.. _gs_gateway_aks:

AKS
===

Prerequisites
-------------

* An AKS cluster created with ``--network-plugin none``
  (`Bring Your Own CNI <https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli>`_
  mode). See :doc:`the AKS installation requirements </installation/requirements-aks>`
  for initial setup instructions.
* ``kubeProxyReplacement=true`` — required by the Gateway API controller.
* ``gatewayAPI.enabled=true`` — enables the Cilium Gateway API controller.
* The Gateway API CRDs must be pre-installed (see :ref:`gs_gateway_api` for
  the full prerequisites list).
* Each Gateway creates an **Azure Load Balancer** automatically via the
  Azure Cloud Controller Manager. No extra IPAM configuration is required.
* Set the pod CIDR to a range that does not overlap with the AKS default
  Service CIDR (``10.0.0.0/16``). The recommended pod CIDR is
  ``192.168.0.0/16``.

Installation
------------

.. code-block:: shell-session

    $ cilium install \
        --datapath-mode=aks-byocni \
        --set kubeProxyReplacement=true \
        --set gatewayAPI.enabled=true \
        --set loadBalancer.l7.backend=envoy \
        --set ipv4.enabled=true \
        --set ipv6.enabled=true \
        --set ipam.operator.clusterPoolIPv4PodCIDRList=192.168.0.0/16 \
        --set ipam.operator.clusterPoolIPv6PodCIDRList=fd00::/104

Or via Helm:

.. code-block:: shell-session

    $ helm upgrade cilium cilium/cilium \
        --namespace kube-system \
        --reuse-values \
        --set kubeProxyReplacement=true \
        --set gatewayAPI.enabled=true \
        --set loadBalancer.l7.backend=envoy \
        --set ipv4.enabled=true \
        --set ipv6.enabled=true \
        --set ipam.operator.clusterPoolIPv4PodCIDRList=192.168.0.0/16 \
        --set ipam.operator.clusterPoolIPv6PodCIDRList=fd00::/104
    $ kubectl -n kube-system rollout restart deployment/cilium-operator
    $ kubectl -n kube-system rollout restart ds/cilium

Verification
------------

.. code-block:: shell-session

    $ kubectl get gateway -A
    NAMESPACE   NAME     CLASS    ADDRESS          PROGRAMMED   AGE
    default     my-gw    cilium   52.154.12.34     True         2m

Known Specifics
---------------

* **Azure CNI Powered by Cilium**: The
  `Azure CNI Powered by Cilium <https://learn.microsoft.com/en-us/azure/aks/azure-cni-powered-by-cilium>`_
  option is a Microsoft-managed deployment of Cilium. In this mode, AKS owns
  the Cilium configuration and ``gatewayAPI.enabled`` cannot be freely set.
  Gateway API is only supported in the BYOCNI (``--network-plugin none``) mode
  described above.
* **IPv4+IPv6 dual-stack**: Dual-stack is supported and tested in CI with
  BYOCNI. Set both ``ipv4.enabled=true`` and ``ipv6.enabled=true``, and
  provide both ``ipam.operator.clusterPoolIPv4PodCIDRList`` and
  ``ipam.operator.clusterPoolIPv6PodCIDRList`` values.
* **Pod CIDR overlap**: Avoid using ``10.0.0.0/8`` as the pod CIDR because
  the AKS default service CIDR (``10.0.0.0/16``) falls within that range.
  Use ``192.168.0.0/16`` (or another non-overlapping range) as shown above.
