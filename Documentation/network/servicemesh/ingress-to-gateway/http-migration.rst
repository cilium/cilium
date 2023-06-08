.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_http_migration:

**********************
HTTP Migration Example
**********************

This example shows you how to migrate an existing Ingress configuration to the equivalent Gateway API resource.

The Cilium :ref:`gs_ingress_http` serves as the starting Ingress configuration. 
The same approach applies to other controllers, though each Ingress controller configuration varies.

The example Ingress configuration routes traffic to backend services from the
``bookinfo`` demo microservices app from the Istio project.

Review Ingress Configuration
============================

You can find the example Ingress definition in ``basic-ingress.yaml``.

.. literalinclude:: ../../../../examples/kubernetes/servicemesh/basic-ingress.yaml

This example listens for traffic on port 80, routes requests for the path ``/details`` to the ``details`` service,
and ``/`` to the ``productpage`` service.


Create Equivalent Gateway Configuration
=======================================

To create the equivalent Gateway configuration, consider the following:

- Entry Point

The entry point is a combination of an IP address and port through which external clients access the data plane.

.. tabs::

    .. group-tab:: Ingress
        
        Every Ingress resource has two implicit entry points -- one for HTTP and the other for HTTPS traffic. 
        An Ingress controller provides the entry points. Typically, entry points are either shared by all Ingress resources, or every Ingress resource has dedicated entry points.

        .. code-block:: shell-session

            apiVersion: networking.k8s.io/v1
            kind: Ingress
            spec:
              ingressClassName: cilium

    .. group-tab:: Gateway API

        In the Gateway API, entry points must be explicitly defined in a Gateway resource. 
        For example, for the data plane to handle HTTP traffic on port 80, you must define a listener for that traffic. 
        Typically, a Gateway implementation provides a dedicated data plane for each Gateway resource.

        .. code-block:: shell-session

            apiVersion: gateway.networking.k8s.io/v1beta1
            kind: Gateway
            metadata:
              name: cilium-gateway
            spec:
              gatewayClassName: cilium
              listeners:
              - name: http
                port: 80
                protocol: HTTP

- Routing Rules

When using Ingress or Gateway API, routing rules must be defined to attach applications to those entry points.

.. tabs::

    .. group-tab:: Ingress
        
        The path-based routing rules are configured in the Ingress resource.

        In the Ingress resource, each hostname has separate routing rules:

        .. code-block:: shell-session

            apiVersion: networking.k8s.io/v1
            kind: Ingress
            [...]
            rules:
            - http:
                paths:
                - backend:
                    service:
                      name: details
                      port:
                        number: 9080
                  path: /details
                  pathType: Prefix
                - backend:
                    service:
                      name: productpage
                      port:
                        number: 9080
                  path: /
                  pathType: Prefix

    .. group-tab:: Gateway API

        The routing rules are configured in the HTTPRoute.

        .. code-block:: shell-session

            ---
            apiVersion: gateway.networking.k8s.io/v1beta1
            kind: HTTPRoute
            spec:
              parentRefs:
              - name: cilium-gateway
            rules:
            - matches:
              - path:
                  type: PathPrefix
                  value: /
              backendRefs:
              - name: productpage
                port: 9080
            - matches:
              - path:
                  type: PathPrefix
                  value: /details
              backendRefs:
              - name: details
                port: 9080
              

- Selecting Data Plane to Attach to:

Both Ingress and Gateway API resources must be explicitly attached to a Dataplane.  

.. tabs::

    .. group-tab:: Ingress

        An Ingress resource must specify a class that selects which Ingress controller to use. 

        .. code-block:: shell-session

            apiVersion: networking.k8s.io/v1
            kind: Ingress
            spec:
              ingressClassName: cilium

    .. group-tab:: Gateway API

        A Gateway resource must also specify a class: in this example, it is always the ``cilium`` class. 
        An HTTPRoute must specify which Gateway (or Gateways) to attach to via a ``parentRef``.

        .. code-block:: shell-session

            apiVersion: gateway.networking.k8s.io/v1beta1
            kind: Gateway
            metadata:
              name: cilium-gateway
              namespace: default
            spec:
              gatewayClassName: cilium
            [...]
            ---
            apiVersion: gateway.networking.k8s.io/v1beta1
            kind: HTTPRoute
            spec:
              parentRefs:
              - name: cilium-gateway


Review Equivalent Gateway Configuration
=======================================

You can find the equivalent final Gateway and HTTPRoute definition in ``http-migration.yaml``.

.. literalinclude:: ../../../../examples/kubernetes/gateway/http-migration.yaml

The preceding example creates a Gateway named ``cilium-gateway`` that listens on port 80 for HTTP traffic.
Two routes are defined, one for ``/details`` to the ``details`` service, and
one for ``/`` to the ``productpage`` service.

Deploy the resources and verify that the HTTP requests are routed successfully to the services.
For more information, consult the Gateway API :ref:`gs_gateway_http`.
