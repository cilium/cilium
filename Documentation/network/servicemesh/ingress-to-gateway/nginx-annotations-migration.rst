.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress_to_gateway_nginx_annotations:

***************************************************
NGINX Ingress Annotations to Gateway API Migration
***************************************************

This page provides a practical migration guide for NGINX Ingress annotations
when moving to Gateway API in Cilium environments.

This guide focuses on common annotation patterns and their closest Gateway API
equivalents or alternatives.

Migration Triage Model
######################

Use this order when migrating annotations:

1. **Direct mapping**: replace the annotation with native Gateway API fields and filters.
2. **Extension-dependent**: migrate only if your environment supports the required experimental or implementation-specific extension.
3. **No equivalent / not planned**: redesign behavior (policy, app, or platform setting) instead of searching for a 1:1 translation.

.. note::

   When a mapping references a GEP or experimental API, verify feature support in
   both your installed Gateway API version and Cilium release. Entries marked
   **Not yet supported** have no Cilium implementation today and may be added in
   future releases.

Inventory Existing NGINX Annotations
####################################

Extract currently used annotations before conversion:

.. code-block:: bash

    kubectl get ingress -A -o json \
      | jq -r '.items[]
      | [.metadata.namespace, .metadata.name,
         ((.metadata.annotations // {}) | to_entries[]
          | select(.key | startswith("nginx.ingress.kubernetes.io/"))
          | "\(.key)=\(.value)")] | @tsv'

Prioritize by frequency and production criticality (auth, redirect, timeout, TLS,
and source restriction annotations first).

Common Direct Mappings
######################

.. list-table::
   :header-rows: 1

   * - NGINX annotation
     - Gateway API equivalent
     - External reference
     - Cilium support
     - Notes
   * - ``canary-weight``
     - ``HTTPRoute.rules.backendRefs[].weight``
     - `Traffic Splitting Guide <https://gateway-api.sigs.k8s.io/guides/traffic-splitting/>`__
     - Yes
     - Weighted traffic splitting.
   * - ``canary-by-header``
     - ``HTTPRoute.rules.matches.headers``
     - `Traffic Splitting Guide <https://gateway-api.sigs.k8s.io/guides/traffic-splitting/>`__
     - Yes
     - Combine with weighted ``backendRefs`` for canary.
   * - ``use-regex``
     - ``HTTPRouteMatch.path.type: RegularExpression``
     - `HTTP Routing Guide <https://gateway-api.sigs.k8s.io/guides/http-routing/>`_
     - Yes
     - Requires Gateway regex path support.
   * - ``rewrite-target``
     - ``HTTPRoute.filters.type: URLRewrite``
     - `Redirects and Rewrites Guide <https://gateway-api.sigs.k8s.io/guides/http-redirect-rewrite/>`__
     - Yes
     - Use per-rule rewrite filters.
   * - ``force-ssl-redirect``
     - ``HTTPRoute.filters.type: RequestRedirect``
     - `Redirects and Rewrites Guide <https://gateway-api.sigs.k8s.io/guides/http-redirect-rewrite/>`__
     - Yes
     - Redirect HTTP to HTTPS at route level.
   * - ``permanent-redirect``
     - ``HTTPRoute.filters.type: RequestRedirect``
     - `Redirects and Rewrites Guide <https://gateway-api.sigs.k8s.io/guides/http-redirect-rewrite/>`__
     - Yes
     - Set permanent redirect behavior.
   * - ``proxy-read-timeout``
     - ``HTTPRoute.rules.timeouts``
     - `HTTP Timeouts Guide <https://gateway-api.sigs.k8s.io/guides/http-timeouts/>`_
     - Yes
     - Map timeout semantics carefully.
   * - ``retry-attempts``
     - ``HTTPRoute.rules.retry.attempts``
     - `GEP-1731 <https://gateway-api.sigs.k8s.io/geps/gep-1731/>`__
     - Yes
     - Experimental in Gateway API (GEP-1731).
   * - ``ingress.class``
     - ``Gateway.spec.gatewayClassName``
     - `Gateway API Overview <https://gateway-api.sigs.k8s.io/concepts/api-overview/>`__
     - Yes
     - Replace controller selection model.
   * - ``server-alias``
     - ``HTTPRoute.spec.hostnames``
     - `Gateway API Overview <https://gateway-api.sigs.k8s.io/concepts/api-overview/>`__
     - Yes
     - Migrate alternate hostnames explicitly.
   * - ``backend-protocol``
     - ``Service.spec.ports[].appProtocol``
     - `GEP-1911 <https://gateway-api.sigs.k8s.io/geps/gep-1911/>`_
     - Yes (enable ``gatewayAPI.enableAppProtocol``)
     - For backend protocol hints.
   * - ``enable-cors``
     - ``HTTPRoute.filters.type: CORS``
     - `GEP-1767 <https://gateway-api.sigs.k8s.io/geps/gep-1767/>`_
     - Not yet supported
     - Experimental in Gateway API (GEP-1767).
   * - ``proxy-ssl-secret``
     - ``BackendTLSPolicy.spec.validation.caCertificateRefs``
     - `BackendTLSPolicy <https://gateway-api.sigs.k8s.io/api-types/backendtlspolicy/>`__
     - Yes
     - Backend TLS trust material.
   * - ``proxy-ssl-verify``
     - ``BackendTLSPolicy.spec.validation``
     - `BackendTLSPolicy <https://gateway-api.sigs.k8s.io/api-types/backendtlspolicy/>`__
     - Yes
     - CA and validation behavior.
   * - ``secure-backends``
     - ``BackendTLSPolicy``
     - `BackendTLSPolicy <https://gateway-api.sigs.k8s.io/api-types/backendtlspolicy/>`__
     - Yes
     - Use policy attachment for backend TLS.

Complex Mappings and Extension-Dependent Cases
################################################

The following annotations do not have a direct Gateway API equivalent today.
Migration depends on implementation-specific extensions or the graduation of
upstream GEPs into the Gateway API standard. Unless noted otherwise, **Cilium
does not yet support these mappings**.

.. list-table::
   :header-rows: 1

   * - NGINX annotation
     - Suggested approach
     - External reference
     - Cilium support
     - Complexity
   * - ``upstream-hash-by``
     - Implementation-specific traffic policy extension
     - -
     - Not yet supported
     - High
   * - ``keep-alive``, ``keepalive-*``, ``upstream-keepalive-*``
     - Implementation-specific data-plane tuning policy
     - -
     - Not yet supported
     - High
   * - ``auth-type``, ``auth-url``
     - ``ExternalAuth``-style HTTPRoute filter (experimental)
     - `GEP-1494 <https://gateway-api.sigs.k8s.io/geps/gep-1494/>`_
     - Not yet supported
     - High
   * - ``auth-tls-secret``, ``auth-tls-verify-client``
     - Frontend/client certificate validation extension
     - `GEP-91 <https://gateway-api.sigs.k8s.io/geps/gep-91/>`_
     - Not yet supported
     - High
   * - ``proxy-next-upstream*``
     - Retry and timeout fields (partly experimental)
     - `GEP-1731 <https://gateway-api.sigs.k8s.io/geps/gep-1731/>`__,
       `GEP-1742 <https://gateway-api.sigs.k8s.io/geps/gep-1742/>`_
     - Not yet supported
     - High
   * - ``tcp-services-configmap``
     - ``TCPRoute`` resources (experimental channel)
     - `TCPRoute <https://gateway-api.sigs.k8s.io/api-types/tcproute/>`_
     - Not yet supported
     - High
   * - ``use-forwarded-headers``
     - Implementation-specific client traffic policy
     - -
     - Not yet supported
     - High
   * - ``whitelist-source-range``
     - Cilium network policy and/or implementation-specific route security filters
     - -
     - Not yet supported
     - High

No Equivalent or Not Planned
############################

These are common examples that do not have a 1:1 Gateway API migration target:

- ``configuration-snippet``, ``server-snippet``, ``server-snippets`` (``won't add``)
- ``sendfile`` (``won't add``)
- ``proxy-store`` (no direct equivalent)
- ``proxy-buffering`` and related proxy buffer tuning annotations
- ``worker-processes`` (``N/A``)

For these cases, prefer one of:

1. Move behavior to application/runtime configuration.
2. Move behavior to dedicated platform policy objects (if available).
3. Drop legacy tuning that is no longer relevant with Gateway API + Envoy.

Validation
##########

For every migrated annotation, validate:

- Route/Gateway condition status (Accepted, Programmed, ResolvedRefs).
- End-to-end behavior parity (redirects, headers, auth, retries, TLS).
- SLO impact during rollout (error rate, latency, retry amplification).

Related Content
###############

- :ref:`gs_ingress-to-gateway`
- :ref:`gs_gateway_http_migration`
- :ref:`gs_gateway_tls_migration`
- :ref:`gs_gateway_api`
