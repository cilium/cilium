.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_tls_migration:

*************
TLS Migration
*************

This migration example builds on the previous :ref:`gs_gateway_http_migration` and add TLS
termination for two HTTP routes. For simplicity, the second route to ``productpage``
is omitted.


Review Ingress Configuration
============================

You'll find the example Ingress definition in ``tls-ingress.yaml``.

.. literalinclude:: ../../../../examples/kubernetes/servicemesh/tls-ingress.yaml

This example:

- listens for HTTPS traffic on port 443.
- terminates TLS for the ``hipstershop.cilium.rocks`` and ``bookinfo.cilium.rocks`` hostnames using the TLS certificate and key from the Secret *demo-cert*.
- routes HTTPS requests for the ``hipstershop.cilium.rocks`` hostname with the URI prefix ``/hipstershop.ProductCatalogService`` to the *productcatalogservice* Service.
- routes HTTPS requests for the ``hipstershop.cilium.rocks`` hostname with the URI prefix ``/hipstershop.CurrencyService`` to the *currencyservice* Service.
- routes HTTPS requests for the ``bookinfo.cilium.rocks`` hostname with the URI prefix ``/details`` to the *details* Service.
- routes HTTPS requests for the ``bookinfo.cilium.rocks`` hostname with any other prefix to the *productpage* Service.


Create Equivalent Gateway Configuration
=======================================

To create the equivalent TLS termination configuration, you must consider the following:

- TLS Termination

.. tabs::

    .. group-tab:: Ingress
        
        The Ingress resource supports TLS termination via the TLS section, where the TLS certificate and key are stored in a Kubernetes Secret.

        .. code-block:: shell-session

            apiVersion: networking.k8s.io/v1
            kind: Ingress
            metadata:
              name: tls-ingress
              namespace: default
            [...]
            spec:
              tls:
              - hosts:
                - bookinfo.cilium.rocks
                - hipstershop.cilium.rocks
                secretName: demo-cert

    .. group-tab:: Gateway API

        In the Gateway API, TLS termination is a property of the Gateway listener, and similarly to the Ingress, a TLS certificate and key are also stored in a Secret.

        .. code-block:: shell-session

            apiVersion: gateway.networking.k8s.io/v1beta1
            kind: Gateway
            metadata:
              name: tls-gateway
            spec:
              gatewayClassName: cilium
              listeners:
              - name: bookinfo.cilium.rocks
                protocol: HTTPS
                port: 443
                hostname: "bookinfo.cilium.rocks"
                tls:
                  certificateRefs:
                  - kind: Secret
                    name: demo-cert
              - name: hipstershop.cilium.rocks
                protocol: HTTPS
                port: 443
                hostname: "hipstershop.cilium.rocks"
                tls:
                  certificateRefs:
                  - kind: Secret
                    name: demo-cert

- Host-header-based Routing Rules

.. tabs::

    .. group-tab:: Ingress
        
        The Ingress API uses the term *host*.
        With Ingress, each host has separate routing rules.

        .. code-block:: shell-session

            apiVersion: networking.k8s.io/v1
            kind: Ingress
            metadata:
              name: tls-ingress
              namespace: default
            spec:
              ingressClassName: cilium
            rules:
            - host: hipstershop.cilium.rocks
                http:
                paths:
                - backend:
                    service:
                        name: productcatalogservice
                        port:
                        number: 3550
                    path: /hipstershop.ProductCatalogService
                    pathType: Prefix

    .. group-tab:: Gateway API

        The Gateway API uses the *hostname* term.
        The host-header-based routing rules map to the hostnames of the HTTPRoute. 
        In the HTTPRoute, the routing rules apply to all hostnames.

        The hostnames of an HTTPRoute must match the hostname of the Gateway listener. Otherwise, the listener will ignore the routing rules for the unmatched hostnames.

        .. code-block:: shell-session

            ---
            apiVersion: gateway.networking.k8s.io/v1beta1
            kind: HTTPRoute
            metadata:
            name: hipstershop-cilium-rocks
            namespace: default
            spec:
              hostnames:
              - hipstershop.cilium.rocks
              parentRefs:
              - name: cilium
              rules:
              - matches:
                - path:
                  type: PathPrefix
                  value: /hipstershop.ProductCatalogService
              backendRefs:
              - name: productcatalogservice
                port: 3550

Review Equivalent Gateway Configuration
=======================================

You'll find the equivalent final Gateway and HTTPRoute definition in ``tls-migration.yaml``.

.. literalinclude:: ../../../../examples/kubernetes/gateway/tls-migration.yaml

Deploy the resources and verify that HTTPS requests are routed successfully to the services.
For more information, consult the Gateway API :ref:`gs_gateway_https`.