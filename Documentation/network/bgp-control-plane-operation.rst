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
