.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Host network mode
*****************

.. note::
    Supported since Cilium 1.16+

Host network mode allows you to expose the Cilium Gateway API Gateway directly
on the host network.
This is useful in cases where a LoadBalancer Service is unavailable, such
as in development environments or environments with cluster-external
loadbalancers.

.. note::
    * Enabling the Cilium Gateway API host network mode automatically disables the LoadBalancer type Service mode. They are mutually exclusive.
    * The listener is exposed on all interfaces (``0.0.0.0`` for IPv4 and/or ``::`` for IPv6).

Host network mode can be enabled via Helm:

.. code-block:: yaml

    gatewayAPI:
      enabled: true
      hostNetwork:
        enabled: true

Once enabled, the host network port for a ``Gateway`` can be specified via
``spec.listeners.port``. The port must be unique per ``Gateway``
resource and you should choose a port number higher than ``1023`` (see
`Bind to privileged port`_).

.. warning::
    Be aware that misconfiguration might result in port clashes. Configure unique ports that are still available on all Cilium Nodes where Gateway API listeners are exposed.

Bind to privileged port
=======================

By default, the Cilium L7 Envoy process does not have any Linux capabilities
out-of-the-box and is therefore not allowed to listen on privileged ports.

If you choose a port equal to or lower than ``1023``, ensure that the Helm value
``envoy.securityContext.capabilities.keepCapNetBindService=true`` is configured
and to add the capability ``NET_BIND_SERVICE`` to the respective
:ref:`Cilium Envoy container via Helm values<envoy>`:

* Standalone DaemonSet mode: ``envoy.securityContext.capabilities.envoy``
* Embedded mode: ``securityContext.capabilities.ciliumAgent``

Configure the following Helm values to allow privileged port bindings in host
network mode:

.. tabs::

    .. group-tab:: Standalone DaemonSet mode

      .. code-block:: yaml

          gatewayAPI:
            enabled: true
            hostNetwork:
              enabled: true
          envoy:
            enabled: true
            securityContext:
              capabilities:
                keepCapNetBindService: true
                envoy:
                # Add NET_BIND_SERVICE to the list (keep the others!)
                - NET_BIND_SERVICE

    .. group-tab:: Embedded mode

      .. code-block:: yaml

          gatewayAPI:
            enabled: true
            hostNetwork:
              enabled: true
          envoy:
            securityContext:
              capabilities:
                keepCapNetBindService: true
          securityContext:
            capabilities:
              ciliumAgent:
              # Add NET_BIND_SERVICE to the list (keep the others!)
              - NET_BIND_SERVICE

Deploy Gateway API listeners on subset of nodes
===============================================

The Cilium Gateway API Envoy listener can be exposed on a specific subset of
nodes. This only works in combination with the host network mode and can be
configured via a node label selector in the Helm values:

.. code-block:: yaml

    gatewayAPI:
      enabled: true
      hostNetwork:
        enabled: true
        nodes:
          matchLabels:
            role: infra
            component: gateway-api

This will deploy the Gateway API Envoy listener only on the Cilium Nodes
matching the configured labels. An empty selector selects all nodes and
continues to expose the functionality on all Cilium nodes.