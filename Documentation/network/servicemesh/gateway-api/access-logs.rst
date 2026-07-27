.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_access_logs:

***********
Access Logs
***********

This example builds on the previous :ref:`gs_gateway_http` and configures `Envoy
access logs`__ for Gateways managed by Cilium Gateway API.

Access logging is managed via the ``spec.telemetry.accessLogs`` field within a
``CiliumGatewayClassConfig`` resource. Since this configuration is referenced by
``GatewayClass`` resource via ``spec.parametersRef``, any settings you define here will automatically
apply to all Gateways using that specific Gateway Class.

Cilium configures Envoy to write access logs to stdout.

Configuration Options
=====================

When configuring access logs, the ``format`` field is required. You can
customize the log output using the following parameters:

* ``format`` (Required): Defines the log output type. Supported values
  are ``Text`` or ``JSON``.

* ``text`` (Optional): A custom Envoy text format string. If you select
  ``format: Text`` but leave this field empty, Cilium falls back to the
  `default Envoy text format`__.

* ``json`` (Optional): A key-value map linking your custom JSON field
  names to Envoy format operators. If you select ``format: JSON`` but leave
  this field empty, Cilium applies a pre-configured JSON template that
  mirrors the information from the default Envoy text format.

  .. note::
     This default JSON mapping is provided by Cilium, not by Envoy's
     built-in defaults.

* ``targets`` (Optional): Specifies the traffic type to log. Supported
  values are ``HTTP`` and ``TCP`` (which includes TLS passthrough). If
  omitted, Cilium defaults to logging ``HTTP`` traffic only.

Custom Cilium formatters
========================

In addition to standard Envoy operators, Cilium provides two Gateway-specific
formatters to help you identify the source of the traffic:

* ``%CILIUM_GATEWAY_NAMESPACE%`` resolves to the namespace of the Gateway.

* ``%CILIUM_GATEWAY_NAME%`` resolves to the name of the Gateway.

For a complete list of all other available format operators,
please refer to the official Envoy access log substitution `formatter documentation`__.

Deploy a Gateway with access logs
=================================

Create a ``CiliumGatewayClassConfig`` that enables JSON access logs for HTTP
traffic:

.. code-block:: yaml

    apiVersion: cilium.io/v2alpha1
    kind: CiliumGatewayClassConfig
    metadata:
      name: cilium
      namespace: default
    spec:
      telemetry:
        accessLogs:
        - format: JSON
          json:
            gateway: "%CILIUM_GATEWAY_NAMESPACE%/%CILIUM_GATEWAY_NAME%"
            start_time: "%START_TIME%"
            method: "%REQUEST_HEADER(:METHOD)%"
            path: "%REQUEST_HEADER(X-ENVOY-ORIGINAL-PATH?:PATH)%"
            protocol: "%PROTOCOL%"
            response_code: "%RESPONSE_CODE%"
            response_flags: "%RESPONSE_FLAGS%"
            bytes_received: "%BYTES_RECEIVED%"
            bytes_sent: "%BYTES_SENT%"
            duration: "%DURATION%"
            authority: "%REQUEST_HEADER(:AUTHORITY)%"
            upstream_host: "%UPSTREAM_HOST%"

Update the ``GatewayClass`` to reference the ``CiliumGatewayClassConfig`` resource:

.. code-block:: yaml

    apiVersion: gateway.networking.k8s.io/v1
    kind: GatewayClass
    metadata:
      name: cilium
    spec:
      controllerName: io.cilium/gateway-controller
      parametersRef:
        group: cilium.io
        kind: CiliumGatewayClassConfig
        name: cilium
        namespace: default

Verify that the GatewayClass configuration is accepted:

.. code-block:: shell-session

    $ kubectl get ciliumgatewayclassconfig cilium
    NAME     ACCEPTED   AGE
    cilium   True       33s

Send a request through the Gateway:

.. code-block:: shell-session

    $ GATEWAY=$(kubectl get gateway my-gateway -o jsonpath='{.status.addresses[0].value}')
    $ curl --fail -s http://"$GATEWAY"/details/1 | jq

Verify access logs
==================

Check the Envoy stdout logs for an access log entry that contains the Gateway
namespace and name.

.. code-block:: shell-session

    $ kubectl -n kube-system logs -l app.kubernetes.io/name=cilium-envoy,app.kubernetes.io/part-of=cilium | grep default/my-gateway
    {"authority":"172.18.255.193","bytes_received":0,"bytes_sent":178,"duration":8,"gateway":"default/my-gateway","method":"GET","path":"/details/1","protocol":"HTTP/1.1","response_code":200,"response_flags":"-","start_time":"2026-07-06T10:10:13.622Z","upstream_host":"10.244.0.221:9080"}

Log HTTP and TCP traffic
========================

To emit access logs for both HTTP and TCP proxy traffic, set both targets:

.. code-block:: yaml

    spec:
      telemetry:
        accessLogs:
        - format: Text
          text: '[%START_TIME%] %CILIUM_GATEWAY_NAMESPACE%/%CILIUM_GATEWAY_NAME% "%REQUEST_HEADER(:METHOD)% %REQUEST_HEADER(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%" %RESPONSE_CODE% %DURATION%'
          targets:
          - HTTP
          - TCP

Multiple access log entries may use the same target. Envoy emits one log entry
for each matching configuration, so duplicate configurations will produce
duplicate log lines.

__ https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage
__ https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage#default-format-string
__ https://www.envoyproxy.io/docs/envoy/latest/configuration/advanced/substitution_formatter
