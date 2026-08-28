.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_session_persistence:

*******************
Session Persistence
*******************

Session persistence directs multiple related requests to the same upstream
endpoint. Cilium supports cookie-based session persistence on individual
``HTTPRoute`` and ``GRPCRoute`` rules that are attached through Gateway API.

The ``sessionPersistence`` field is experimental in Gateway API. Install the
experimental ``HTTPRoute`` and ``GRPCRoute`` CRDs as described in
:ref:`gs_gateway_api_prerequisites` before using this feature.

.. note::

    Session persistence is not supported for GAMMA routes whose parent is a
    ``Service``. Cilium rejects such a route with an ``Accepted`` condition set
    to ``False`` and the ``UnsupportedValue`` reason.

Configure session persistence
#############################

Session persistence is configured per route rule. Each rule that requires
persistence must set ``sessionPersistence``. Rules without this field continue
to use normal load balancing.

The following ``HTTPRoute`` rule uses an explicitly named session cookie:

.. code-block:: yaml

    apiVersion: gateway.networking.k8s.io/v1
    kind: HTTPRoute
    metadata:
      name: persistent-http-route
    spec:
      parentRefs:
      - name: tls-gateway
      hostnames:
      - app.example.com
      rules:
      - matches:
        - path:
            type: PathPrefix
            value: /api
        backendRefs:
        - name: app-v1
          port: 8080
          weight: 50
        - name: app-v2
          port: 8080
          weight: 50
        sessionPersistence:
          type: Cookie
          sessionName: app-session
          cookieConfig:
            lifetimeType: Session

The first request is load balanced normally. The response sets the
``app-session`` cookie, and subsequent requests that include that cookie are
directed to the same upstream endpoint.

The default value for the ``type`` field is ``Cookie``, and is currently the
only supported value. Similarly, the default and only supported value for the
``cookieConfig.lifetimeType`` is ``Session``. These fields can be safely omitted.

The same field is available on a ``GRPCRoute`` rule:

.. code-block:: yaml

    apiVersion: gateway.networking.k8s.io/v1
    kind: GRPCRoute
    metadata:
      name: persistent-grpc-route
    spec:
      parentRefs:
      - name: tls-gateway
      rules:
      - matches:
        - method:
            service: example.v1.ExampleService
        backendRefs:
        - name: grpc-app
          port: 7070
        sessionPersistence:
          sessionName: grpc-session

Cookie behavior
===============

Cilium configures session persistence cookies as follows:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Behavior
   * - Name
     - Cilium uses ``sessionName`` when it is set. If it is omitted, Cilium
       generates a name beginning with ``cilium-gw-session-`` from the route
       kind, namespace, name, and rule position. Set an explicit name if the
       name must remain stable when rules are reordered.  When choosing a name,
       ensure that it is unique among routes serving the same hostname with
       overlapping cookie paths.
   * - Path
     - Cilium uses an exact or prefix route path when one is available, or
       defaults to ``/``.
   * - Lifetime
     - The cookie is a session cookie. Cilium does not set ``Max-Age`` or
       ``Expires`` attributes.
   * - Attributes
     - Cilium always sets ``Secure``, ``HttpOnly``, and ``SameSite=Strict``.
       These attributes are not configurable.
   * - Unavailable endpoint
     - If the endpoint encoded in the cookie is unavailable, Cilium falls back
       to normal load balancing and updates the session cookie for the newly
       selected endpoint.

Because the cookie always has the ``Secure`` attribute, web browsers only send
it over HTTPS. Configure a TLS listener as described in
:ref:`gs_gateway_https` when browser clients use session persistence.

Supported fields
================

Cilium supports the following Gateway API fields and values:

.. list-table::
   :header-rows: 1

   * - Field
     - Supported values
     - Unsupported values
   * - ``type``
     - ``Cookie`` (default)
     - ``Header``
   * - ``sessionName``
     - A valid, non-empty HTTP cookie name, or omitted to let Cilium generate
       a name
     - An empty or invalid HTTP cookie name
   * - ``cookieConfig.lifetimeType``
     - ``Session`` (default)
     - ``Permanent``
   * - ``absoluteTimeout``
     - None (unsupported)
     - Any specified duration

When a route uses an unsupported value, Cilium sets its ``Accepted`` condition
to ``False`` with the ``UnsupportedValue`` reason. Inspect the route status for
the specific validation message:

.. code-block:: shell-session

    $ kubectl describe httproute <route-name>
    $ kubectl describe grpcroute <route-name>

Security considerations
=======================

The persistence cookie identifies an upstream endpoint. Its contents are not
signed or encrypted, so clients can inspect or modify them. Do not use the
cookie as proof of authentication or as an application session identity.
