.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bgp_control_plane_operation:

BGP Control Plane Operation Guide
#################################

This document provides guidance on how to operate the BGP Control Plane.

Failure Scenarios
=================

This document describes common failure scenarios that you may encounter when
using the BGP Control Plane and provides guidance on how to mitigate them.

Cilium Agent Down
-----------------

If the Cilium agent goes down, the BGP session will be lost because the BGP
speaker is integrated within the Cilium agent. The BGP session will be restored
once the Cilium agent is restarted. However, while the Cilium agent is down,
the advertised routes will be removed from the BGP peer. As a result, you may
temporarily lose connectivity to the Pods or Services.

Mitigation
~~~~~~~~~~

The recommended way to address this issue is by enabling the
:ref:`bgp_control_plane_graceful_restart` feature. This feature allows the BGP
peer to retain routes for a specific period of time after the BGP session is
lost. Since the datapath remains active even when the agent is down, this will
prevent the loss of connectivity to the Pods or Services.

When you can't use BGP Graceful Restart, you can take the following actions,
depending on the kind of routes you are using:

PodCIDR routes
++++++++++++++

If you are advertising PodCIDR routes, pods on the failed node will be
unreachable from the external network. If the failure only occurs on a subset
of the nodes in the cluster, you can drain the unhealthy nodes to migrate the
pods to other nodes.

Service routes
++++++++++++++

If you are advertising service routes, the load balancer (KubeProxy or Cilium
KubeProxyReplacement) may become unreachable from the external network.
Additionally, ongoing connections may be redirected to different nodes due to
ECMP rehashing on the upstream routers. When the load balancer encounters
unknown traffic, it will select a new endpoint. Depending on the load
balancer's backend selection algorithm, the traffic may be directed to a
different endpoint than before, potentially causing the connection to be reset.

If your upstream routers support ECMP with `Resilient Hashing`_, enabling
it may help to keep the ongoing connections forwarded to the same node.
Enabling the :ref:`maglev` feature in Cilium may also help since it increases
the probability that all nodes select the same endpoint for the same flow.
However, it only works for the ``externalTrafficPolicy: Cluster``. If the
Service's ``externalTrafficPolicy`` is set to ``Local``, it is inevitable that
all ongoing connections with the endpoints on the failed node, and connections
forwarded to a different node than before, will be reset.

.. _Resilient Hashing: https://www.juniper.net/documentation/us/en/software/junos/interfaces-ethernet-switches/topics/topic-map/switches-interface-resilient-hashing.html

Peering Link Down
-----------------

If the peering link between the BGP peers goes down, usually, both the BGP
session and datapath connectivity will be lost. However, there may be a period
during which the datapath connectivity is lost while the BGP session remains up
and routes are still being advertised. This can cause the BGP peer to send
traffic over the failed link, resulting in dropped packets. The length of this
period depends on which link is down and the BGP configuration.

If the link directly connected to the Node goes down, the BGP session will
likely be lost immediately because the Linux kernel detects the link failure
and shuts down the TCP session right away. If a link not directly connected to
the Node goes down, the BGP session will be lost after the hold timer expires,
which is set to 90 seconds by default.

Mitigation
~~~~~~~~~~

To make link detection failure fast, you can adjust ``holdTimeSeconds`` and
``keepAliveTimeSeconds`` in the BGP configuration to the shorter value.
However, the minimal possible values are ``holdTimeSeconds=3`` and
``keepAliveTimeSeconds=1``. The general approach to make failure detection faster is to
use BFD (Bidirectional Forwarding Detection), but currently, Cilium does not
support it.

Cilium Operator Down
--------------------

If the Cilium Operator goes down, PodCIDR allocation by IPAM, and LoadBalancer
IP allocation by LB-IPAM are stopped. Therefore, the advertisement of new
and withdrawal of old PodCIDR and Service VIP routes will be stopped as well.

Mitigation
~~~~~~~~~~

There's no direct mitigation in terms of the BGP. However, running the Cilium
Operator with a :ref:`high-availability setup <cilium_operator_internals>` will
make the Cilium Operator more resilient to failures.

Service Losing All Backends
---------------------------

If all service backends are gone due to an outage or a configuration mistake, BGP
Control Plane behaves differently depending on the Service's
``externalTrafficPolicy``. When the ``externalTrafficPolicy`` is set to
``Cluster``, the Service's VIP remains advertised from all nodes selected by the
CiliumBGPPeeringPolicy. When the ``externalTrafficPolicy`` is set to ``Local``,
the advertisement stops entirely because the Service's VIP is only advertised
from the node where the Service backends are running.

Mitigation
~~~~~~~~~~

There's no direct mitigation in terms of the BGP. In general, you should
prevent the Service backends from being all gone by Kubernetes features like
PodDisruptionBudget.
