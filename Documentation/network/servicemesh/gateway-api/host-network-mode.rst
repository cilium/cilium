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
    Be aware that misconfiguration might result in port clashes. For each gateway, configure unique ports that are still available on all Cilium Nodes where Gateway API listeners are exposed.

The ``GatewayStatusAddress`` field for a gateway has a maximum of 16 addresses. Cilium with host network mode enabled will automatically sort the node addresses to allow for consistency, ensuring that the same addresses are selected.

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

Cilium proxies ``HTTPRoute``, ``GRPCRoute``, and ``TLSRoute`` traffic through
Envoy. Cilium's eBPF service load balancer programs ``TCPRoute`` and
``UDPRoute`` directly, bypassing Envoy. The route type therefore determines
which mechanism controls node exposure for the listeners of a ``Gateway``.

For ``HTTPRoute``, ``GRPCRoute``, and ``TLSRoute``, restrict node exposure by
configuring a node label selector in the Helm values. This only works in
combination with the host network mode:

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

For ``TCPRoute`` and ``UDPRoute``, this selector has no effect. Their Service
remains installed on every Cilium node regardless of the selector. To
restrict node exposure for these route types, use the
:ref:`Selective Service Node Exposure` annotation
``service.cilium.io/node-selector`` within
``spec.infrastructure.annotations`` on the ``Gateway`` instead.

If a ``Gateway`` combines both categories of route types, configure both
mechanisms with the same label selector to keep node exposure consistent
across all routes.