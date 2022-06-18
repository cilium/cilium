.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _egress-gateway:

**************
Egress Gateway
**************

.. note::

    Egress Gateway requires a 5.2 or more recent kernel.

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

Compatibility with other features
=================================

L7 policies
-----------

Egress gateway is currently partially incompatible with L7 policies.
Specifically, when an egress gateway policy and an L7 policy both select the same
endpoint, traffic from that endpoint will not go through egress gateway, even if
the policy allows it. Full support will be added in an upcoming release once
:gh-issue:`19642` is resolved.

LB acceleration
---------------

When the egress gateway feature is used in combination with XDP-based LB
acceleration (``--bpf-lb-acceleration=native``), the user must ensure that the
host Iptables configuration allows packets through the ``FORWARD`` chain. Full
support will be added in an upcoming release once :gh-issue:`19717` is resolved.

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
               --set kubeProxyReplacement=strict \\
               --set l7Proxy=false

    .. group-tab:: ConfigMap

        .. code-block:: yaml

            enable-bpf-masquerade: true
            enable-ipv4-egress-gateway: true
            enable-l7-proxy: false
            kube-proxy-replacement: strict

Compatibility with cloud environments
-------------------------------------

Based on the specific configuration of the cloud provider and network interfaces
it is possible that traffic leaves a node from the wrong interface.

To work around this issue, Cilium can be instructed to install the necessary IP
rules and routes to route traffic through the appropriate network-facing
interface as follow:

.. tabs::
    .. group-tab:: Helm

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
            [..] \\
            --set egressGateway.installRoutes=true

    .. group-tab:: ConfigMap

        .. code-block:: yaml

            install-egress-gateway-routes: true

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

   Regardless of which way the egress IP is configured, the user must ensure that
   Cilium is running on the device that has the egress IP assigned to it, by
   setting the ``--devices`` agent option accordingly.

   .. code-block:: yaml

     egressGateway:
       nodeSelector:
         matchLabels:
           testLabel: testVal

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

Apply the ``egress-sample`` egress gateway Policy, which will cause all traffic
from the mediabot pod to leave the cluster with the ``10.168.60.100`` IP:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-egress-gateway/egress-nat-policy-egress-gateway.yaml

Verify the setup
----------------

We can now verify with the client pod that the policy is working correctly:

.. code-block:: shell-session

    $ kubectl exec mediabot -- curl http://192.168.60.13:80
    <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
    [...]

The access log from Nginx should show that the request is coming from the egress
IP (``192.168.60.100``) rather than one of the nodes in the Kubernetes cluster:

.. code-block:: shell-session

    $ tail /var/log/nginx/access.log
    [...]
    192.168.60.100 - - [04/Apr/2021:22:06:57 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.52.1"
