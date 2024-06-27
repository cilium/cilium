.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _egress-gateway:

**************
Egress Gateway
**************

The egress gateway feature routes all IPv4 connections originating from pods and
destined to specific cluster-external CIDRs through particular nodes, from now
on called "gateway nodes".

When the egress gateway feature is enabled and egress gateway policies are in
place, matching packets that leave the cluster are masqueraded with selected,
predictable IPs associated with the gateway nodes. As an example, this feature
can be used in combination with legacy firewalls to allow traffic to legacy
infrastructure only from specific pods within a given namespace. The pods
typically have ever-changing IP addresses, and even if masquerading was to be
used as a way to mitigate this, the IP addresses of nodes can also change
frequently over time.

This document explains how to enable the egress gateway feature and how to
configure egress gateway policies to route and SNAT the egress traffic for a
specific workload.

.. note::

    This guide assumes that Cilium has been correctly installed in your
    Kubernetes cluster. Please see :ref:`k8s_quick_install` for more
    information. If unsure, run ``cilium status`` and validate that Cilium is up
    and running.

.. admonition:: Video
  :class: attention

  For more insights on Cilium's Egress Gateway, check out `eCHO episode 76: Cilium Egress Gateway <https://www.youtube.com/watch?v=zEQdgNGa7bg>`__.

Preliminary Considerations
==========================

Cilium must make use of network-facing interfaces and IP addresses present on
the designated gateway nodes. These interfaces and IP addresses must be
provisioned and configured by the operator based on their networking
environment. The process is highly-dependent on said networking environment. For
example, in AWS/EKS, and depending on the requirements, this may mean creating
one or more Elastic Network Interfaces with one or more IP addresses and
attaching them to instances that serve as gateway nodes so that AWS can
adequately route traffic flowing from and to the instances. Other cloud
providers have similar networking requirements and constructs.

Additionally, the enablement of the egress gateway feature requires that both
BPF masquerading and the kube-proxy replacement are enabled, which may not be
possible in all environments (due to, e.g., incompatible kernel versions).

Delay for enforcement of egress policies on new pods
----------------------------------------------------

When new pods are started, there is a delay before egress gateway policies are
applied for those pods. That means traffic from those pods may leave the
cluster with a source IP address (pod IP or node IP) that doesn't match the
egress gateway IP. That egressing traffic will also not be redirected through
the gateway node.

.. _egress-gateway-incompatible-features:

Incompatibility with other features
-----------------------------------

Because egress gateway isn't compatible with identity allocation mode ``kvstore``,
you must use Kubernetes as Cilium's identity store (``identityAllocationMode``
set to ``crd``). This is the default setting for new installations.

Egress gateway is not compatible with the Cluster Mesh feature. The gateway selected
by an egress gateway policy must be in the same cluster as the selected pods.

Egress gateway is not compatible with the CiliumEndpointSlice feature
(see :gh-issue:`24833` for details).

Egress gateway is not supported for IPv6 traffic.

Enable egress gateway
=====================

The egress gateway feature and all the requirements can be enabled as follow:

.. tabs::
    .. group-tab:: Helm

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
               --namespace kube-system \\
               --reuse-values \\
               --set egressGateway.enabled=true \\
               --set bpf.masquerade=true \\
               --set kubeProxyReplacement=true

    .. group-tab:: ConfigMap

        .. code-block:: yaml

            enable-bpf-masquerade: true
            enable-ipv4-egress-gateway: true
            kube-proxy-replacement: true

Rollout both the agent pods and the operator pods to make the changes effective:

.. code-block:: shell-session

    $ kubectl rollout restart ds cilium -n kube-system
    $ kubectl rollout restart deploy cilium-operator -n kube-system

Writing egress gateway policies
===============================

The API provided by Cilium to drive the egress gateway feature is the
``CiliumEgressGatewayPolicy`` resource.

Metadata
--------

``CiliumEgressGatewayPolicy`` is a cluster-scoped custom resource definition, so a
``.metadata.namespace`` field should not be specified.

.. code-block:: yaml

    apiVersion: cilium.io/v2
    kind: CiliumEgressGatewayPolicy
    metadata:
      name: example-policy

To target pods belonging to a given namespace only labels/expressions should be
used instead (as described below).

Selecting source pods
---------------------

The ``selectors`` field of a ``CiliumEgressGatewayPolicy`` resource is used to
select source pods via a label selector. This can be done using ``matchLabels``:

.. code-block:: yaml

    selectors:
    - podSelector:
        matchLabels:
          labelKey: labelVal

It can also be done using ``matchExpressions``:

.. code-block:: yaml

    selectors:
    - podSelector:
        matchExpressions:
        - {key: testKey, operator: In, values: [testVal]}
        - {key: testKey2, operator: NotIn, values: [testVal2]}

Moreover, multiple ``podSelector`` can be specified:

.. code-block:: yaml

    selectors:
    - podSelector:
      [..]
    - podSelector:
      [..]

To select pods belonging to a given namespace, the special
``io.kubernetes.pod.namespace`` label should be used.

.. note::
    Only security identities will be taken into account.
    See :ref:`identity-relevant-labels` for more information.

Selecting the destination
-------------------------

One or more IPv4 destination CIDRs can be specified with ``destinationCIDRs``:

.. code-block:: yaml

    destinationCIDRs:
    - "a.b.c.d/32"
    - "e.f.g.0/24"

.. note::

    Any IP belonging to these ranges which is also an internal cluster IP (e.g.
    pods, nodes, Kubernetes API server) will be excluded from the egress gateway
    SNAT logic.

It's possible to specify exceptions to the ``destinationCIDRs`` list with
``excludedCIDRs``:

.. code-block:: yaml

    destinationCIDRs:
    - "a.b.0.0/16"
    excludedCIDRs:
    - "a.b.c.0/24"

In this case traffic destined to the ``a.b.0.0/16`` CIDR, except for the
``a.b.c.0/24`` destination, will go through egress gateway and leave the cluster
with the designated egress IP.

Selecting and configuring the gateway node
------------------------------------------

The node that should act as gateway node for a given policy can be configured
with the ``egressGateway`` field. The node is matched based on its labels, with
the ``nodeSelector`` field:

.. code-block:: yaml

  egressGateway:
    nodeSelector:
      matchLabels:
        testLabel: testVal

.. note::

    In case multiple nodes are a match for the given set of labels, the
    first node in lexical ordering based on their name will be selected.

.. note::

    If there is no match for the given set of labels, Cilium drops the
    traffic that matches the destination CIDR(s).

The IP address that should be used to SNAT traffic must also be configured.
There are 3 different ways this can be achieved:

1. By specifying the interface:

   .. code-block:: yaml

     egressGateway:
       nodeSelector:
         matchLabels:
           testLabel: testVal
       interface: ethX

   In this case the first IPv4 address assigned to the ``ethX`` interface will be used.

2. By explicitly specifying the egress IP:

   .. code-block:: yaml

     egressGateway:
       nodeSelector:
         matchLabels:
           testLabel: testVal
       egressIP: a.b.c.d

   .. warning::

     The egress IP must be assigned to a network device on the node.

3. By omitting both ``egressIP`` and ``interface`` properties, which will make
   the agent use the first IPv4 assigned to the interface for the default route.

   .. code-block:: yaml

     egressGateway:
       nodeSelector:
         matchLabels:
           testLabel: testVal

Regardless of which way the egress IP is configured, the user must ensure that
Cilium is running on the device that has the egress IP assigned to it, by
setting the ``--devices`` agent option accordingly.

.. warning::

   The ``egressIP`` and ``interface`` properties cannot both be specified in the ``egressGateway`` spec. Egress Gateway Policies that contain both of these properties will be ignored by Cilium.

Example policy
--------------

Below is an example of a ``CiliumEgressGatewayPolicy`` resource that conforms to
the specification above:

.. code-block:: yaml

  apiVersion: cilium.io/v2
  kind: CiliumEgressGatewayPolicy
  metadata:
    name: egress-sample
  spec:
    # Specify which pods should be subject to the current policy.
    # Multiple pod selectors can be specified.
    selectors:
    - podSelector:
        matchLabels:
          org: empire
          class: mediabot
          # The following label selects default namespace
          io.kubernetes.pod.namespace: default

    # Specify which destination CIDR(s) this policy applies to.
    # Multiple CIDRs can be specified.
    destinationCIDRs:
    - "0.0.0.0/0"

    # Configure the gateway node.
    egressGateway:
      # Specify which node should act as gateway for this policy.
      nodeSelector:
        matchLabels:
          node.kubernetes.io/name: a-specific-node

      # Specify the IP address used to SNAT traffic matched by the policy.
      # It must exist as an IP associated with a network interface on the instance.
      egressIP: 10.168.60.100

      # Alternatively it's possible to specify the interface to be used for egress traffic.
      # In this case the first IPv4 assigned to that interface will be used as egress IP.
      # interface: enp0s8

Creating the ``CiliumEgressGatewayPolicy`` resource above would cause all
traffic originating from pods with the ``org: empire`` and ``class: mediabot``
labels in the ``default`` namespace and destined to ``0.0.0.0/0`` (i.e. all
traffic leaving the cluster) to be routed through the gateway node with the
``node.kubernetes.io/name: a-specific-node`` label, which will then SNAT said
traffic with the ``10.168.60.100`` egress IP.

Selection of the egress network interface
=========================================

For gateway nodes with multiple network interfaces, Cilium selects the egress
network interface based on the node's routing setup
(``ip route get <externalIP> from <egressIP>``).

.. warning::

   Redirecting to the correct egress network interface can fail under certain
   conditions when using a pre-5.10 kernel. In this case Cilium falls back to
   the current (== default) network interface.

   For environments that strictly require traffic to leave through the
   correct egress interface (for example EKS in ENI mode), it is recommended to use
   a 5.10 kernel or newer.

Testing the egress gateway feature
==================================

In this section we are going to show the necessary steps to test the feature.
First we deploy a pod that connects to a cluster-external service. Then we apply
a ``CiliumEgressGatewayPolicy`` and observe that the pod's connection gets
redirected through the Gateway node.
We assume a 2-node cluster with IPs ``192.168.60.11`` (node1) and
``192.168.60.12`` (node2). The client pod gets deployed to node1, and the CEGP
selects node2 as Gateway node.

Create an external service (optional)
-------------------------------------

If you don't have an external service to experiment with, you can use Nginx, as
the server access logs will show from which IP address the request is coming.

Create an nginx service on a Linux node that is external to the existing Kubernetes
cluster, and use it as the destination of the egress traffic:

.. code-block:: shell-session

    $ # Install and start nginx
    $ sudo apt install nginx
    $ sudo systemctl start nginx

In this example, the IP associated with the host running the Nginx instance will
be ``192.168.60.13``.

Deploy client pods
------------------

Deploy a client pod that will be used to connect to the Nginx instance:

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-sw-app.yaml
    $ kubectl get pods
    NAME                             READY   STATUS    RESTARTS   AGE
    pod/mediabot                     1/1     Running   0          14s

    $ kubectl exec mediabot -- curl http://192.168.60.13:80

Verify from the Nginx access log (or other external services) that the request
is coming from one of the nodes in the Kubernetes cluster. In this example the
access logs should contain something like:

.. code-block:: shell-session

    $ tail /var/log/nginx/access.log
    [...]
    192.168.60.11 - - [04/Apr/2021:22:06:57 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.52.1"

since the client pod is running on the node ``192.168.60.11`` it is expected
that, without any Cilium egress gateway policy in place, traffic will leave the
cluster with the IP of the node.

Apply egress gateway policy
---------------------------

Download the ``egress-sample`` Egress Gateway Policy yaml:

.. parsed-literal::

    $ wget \ |SCM_WEB|\/examples/kubernetes-egress-gateway/egress-gateway-policy.yaml

Modify the ``destinationCIDRs`` to include the IP of the host where your
designated external service is running on.

Specifying an IP address in the ``egressIP`` field is optional.
To make things easier in this example, it is possible to comment out that line.
This way, the agent will use the first IPv4 assigned to the interface for the
default route.

To let the policy select the node designated to be the Egress Gateway, apply the
label ``egress-node: true`` to it:

.. code-block:: shell-session

    $ kubectl label nodes <egress-gateway-node> egress-node=true

Note that the Egress Gateway node should be a different node from the one where
the ``mediabot`` pod is running on.

Apply the ``egress-sample`` egress gateway Policy, which will cause all traffic
from the mediabot pod to leave the cluster with the IP of the Egress Gateway node:

.. code-block:: shell-session

    $ kubectl apply -f egress-gateway-policy.yaml

Verify the setup
----------------

We can now verify with the client pod that the policy is working correctly:

.. code-block:: shell-session

    $ kubectl exec mediabot -- curl http://192.168.60.13:80
    <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
    [...]

The access log from Nginx should show that the request is coming from the
selected Egress IP rather than the one of the node where the pod is running:

.. code-block:: shell-session

    $ tail /var/log/nginx/access.log
    [...]
    192.168.60.100 - - [04/Apr/2021:22:06:57 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.52.1"

Troubleshooting
---------------

To troubleshoot a policy that is not behaving as expected, you can view the
egress configuration in a cilium agent (the configuration is propagated to all agents,
so it shouldn't matter which one you pick).

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg bpf egress list
    Defaulted container "cilium-agent" out of: cilium-agent, config (init), mount-cgroup (init), apply-sysctl-overwrites (init), mount-bpf-fs (init), wait-for-node-init (init), clean-cilium-state (init)
    Source IP    Destination CIDR    Egress IP   Gateway IP
    192.168.2.23 192.168.60.13/32    0.0.0.0     192.168.60.12

The Source IP address matches the IP address of each pod that matches the
policy's ``podSelector``. The Gateway IP address matches the (internal) IP address
of the egress node that matches the policy's ``nodeSelector``. The Egress IP is
0.0.0.0 on all agents except for the one running on the egress gateway node,
where you should see the Egress IP address being used for this traffic (which
will be the ``egressIP`` from the policy, if specified).

If the egress list shown does not contain entries as expected to match your
policy, check that the pod(s) and egress node are labeled correctly to match
the policy selectors.

Troubleshooting SNAT Connection Limits
--------------------------------------

For more advanced troubleshooting topics please see advanced egress gateway troubleshooting topic for :ref:`SNAT connection limits<snat_connection_limits>`.

