.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_ext_proc:

***********************************************
External Processing (ext_proc) Filter Example
***********************************************

Cilium supports attaching an Envoy
`External Processing <https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter>`__
(ext_proc) filter to individual HTTPRoute or GRPCRoute rules using the
Gateway API ``ExtensionRef`` filter type. The ext_proc filter sends HTTP
request and response data to an external gRPC service for inspection or
mutation before forwarding to the backend.

This feature uses the ``CiliumEnvoyExtProcFilter`` CRD to define the ext_proc
filter configuration. The CRD is namespace-scoped and is referenced from route
rules via ``ExtensionRef``.

.. Note::

    This feature must be explicitly enabled with the Helm value
    ``gatewayAPI.enableExtensionRefFilters=true`` or the equivalent CLI flag
    ``--enable-gateway-api-extension-ref-filters``.

.. include:: ../echo-app.rst

Enable the Feature
==================

Install or upgrade Cilium with the feature flag enabled:

.. code-block:: shell-session

    $ helm upgrade cilium cilium/cilium --reuse-values \
        --set gatewayAPI.enableExtensionRefFilters=true

Deploy the ext_proc Filter
==========================

The example below deploys a Gateway, an HTTPRoute with two rules, a
``CiliumEnvoyExtProcFilter``, and a minimal ext_proc gRPC service. Only
the ``/api`` rule references the ext_proc filter; requests to ``/``
are forwarded without external processing.

.. Note::

    The example includes a placeholder image for the ext_proc server
    Deployment. Replace the ``ext-proc-service`` container image with your
    own implementation of the
    `Envoy External Processing API <https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto>`__
    before applying to a production cluster.

.. literalinclude:: ../../../../examples/kubernetes/gateway/ext-proc.yaml
     :language: yaml

Deploy the resources:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/ext-proc.yaml

Verify the Gateway is ready:

.. code-block:: shell-session

    $ kubectl get gateway ext-proc-gateway
    NAME                CLASS    ADDRESS          PROGRAMMED   AGE
    ext-proc-gateway    cilium   172.18.255.200   True         30s

.. Note::

    Some providers like EKS use a fully-qualified domain name rather than an IP address.

Make HTTP Requests
==================

Requests to ``/api`` pass through the ext_proc filter before reaching the
backend. The external processor can inspect or modify headers, and the
response reflects any changes it makes.

.. code-block:: shell-session

    $ GATEWAY=$(kubectl get gateway ext-proc-gateway -o jsonpath='{.status.addresses[0].value}')
    $ curl --fail -s http://"$GATEWAY"/api

Requests to ``/`` bypass the ext_proc filter entirely:

.. code-block:: shell-session

    $ curl --fail -s http://"$GATEWAY"/

Operational Responsibility
==========================

``CiliumEnvoyExtProcFilter`` is an advanced integration point. Cilium is
responsible for resolving the Gateway API ``ExtensionRef``, enforcing
``ReferenceGrant`` for cross-namespace backend references, and generating the
Envoy configuration that connects Gateway traffic to the external processor.

.. Note::

    When ExternalAuth (``ext_authz``) is also configured on the same Gateway,
    Envoy processes ``ext_authz`` before ``ext_proc`` in the HTTP filter chain.
    The ext_proc service therefore sees only requests that have already passed
    authorization, and any header mutations by ext_proc occur after the
    authorization decision.

The external processor implementation is owned by the operator. This includes
security policy behavior, WAF rules, processor availability, processor latency,
scaling, and any domain-specific allow/block decision metrics. Cilium exposes
Envoy-side health signals for the ext_proc hop, but it does not validate or
support arbitrary processor or WAF policy semantics.

Observability and Metrics
=========================

Cilium exposes Envoy metrics through the existing cilium-envoy Prometheus
endpoint. If you are using Prometheus Operator, enable the Envoy
``ServiceMonitor`` with ``envoy.prometheus.serviceMonitor.enabled=true``. In
non-``ServiceMonitor`` setups, the Helm chart adds Prometheus scrape annotations
when Envoy Prometheus metrics are enabled.

The cilium-envoy metrics endpoint uses ``envoy.prometheus.port`` (default
``9964``). In standalone Envoy mode, you can inspect the metrics with:

.. code-block:: shell-session

    $ kubectl -n kube-system port-forward svc/cilium-envoy 9964:9964
    $ curl -s localhost:9964/metrics | grep ext_proc

When Envoy runs inside the Cilium agent instead of the standalone Envoy
DaemonSet, scrape or port-forward the agent's Envoy metrics endpoint instead.
See :ref:`metrics` for the general Cilium and Envoy metrics configuration.

Envoy emits ext_proc counters in the HTTP connection manager stats scope. Cilium
sets an Envoy ``stat_prefix`` derived from the ``CiliumEnvoyExtProcFilter``
resource identity using the format ``ceepf.<namespace>.<name>`` (with ``-`` and
``.`` replaced by ``_``). For a filter named ``my-ext-proc`` in namespace
``default``, the stat_prefix is ``ceepf.default.my_ext_proc``. This allows
multiple ext_proc filters on the same Gateway to be distinguished in Envoy
metrics without adding a Cilium-specific metric API.

The most useful Envoy ext_proc counters are:

================================== ==============================================================
Counter                            Meaning
================================== ==============================================================
``streams_started``                gRPC streams opened to the external processor.
``stream_msgs_sent``               Processing messages sent to the external processor.
``stream_msgs_received``           Processing messages received from the external processor.
``streams_failed``                 gRPC stream errors between Envoy and the external processor.
``message_timeouts``               Processor responses that exceeded ``messageTimeout``.
``failure_mode_allowed``           Fail-open events when ``failureModeAllow`` allowed forwarding.
``spurious_msgs_received``         Protocol/order errors from the external processor.
``rejected_header_mutations``      Header mutations rejected by Envoy.
``immediate_responses_sent``       Responses generated directly by the external processor.
================================== ==============================================================

For security-sensitive use cases such as WAFs, alert on non-zero rates of
``message_timeouts``, ``streams_failed``, ``failure_mode_allowed``,
``spurious_msgs_received``, and ``rejected_header_mutations``. A non-zero
``failure_mode_allowed`` rate means requests continued without successful
external processing.

Envoy metric names are flattened and sanitized when exposed as Prometheus
metrics. Prefer discovering the exact names from the running metrics endpoint.
For example:

.. code-block:: promql

    sum(rate({__name__=~"envoy_http_.*_ext_proc_.*message_timeouts.*"}[5m]))

.. code-block:: promql

    sum(rate({__name__=~"envoy_http_.*_ext_proc_.*failure_mode_allowed.*"}[5m]))

Hubble HTTP metrics remain useful for end-to-end Gateway request visibility, but
they do not isolate how much time a request spent in the internal Envoy ext_proc
side stream. For latency SLOs, expose Prometheus metrics from the external
processor itself, such as gRPC/server latency histograms, queue depth, resource
usage, and processor-specific allow/block decision counters.

CiliumEnvoyExtProcFilter Reference
==================================

The ``CiliumEnvoyExtProcFilter`` CRD accepts the following fields. The
resource can also be referenced by its short name ``ceepf``, for example
``kubectl get ceepf``.

``backendRef`` (required)
    Reference to the Kubernetes Service that implements the ext_proc gRPC
    protocol. Includes ``name``, ``port``, and an optional ``namespace``
    (cross-namespace references require a ``ReferenceGrant``).

``processingMode`` (optional)
    Controls which parts of the HTTP request and response are sent to the
    ext_proc service. Sub-fields: ``requestHeaderMode``,
    ``responseHeaderMode``, ``requestBodyMode``, ``responseBodyMode``,
    ``requestTrailerMode``, ``responseTrailerMode``.

``failureModeAllow`` (optional, default ``false``)
    When ``false`` (fail-closed), requests fail if the ext_proc service is
    unreachable. When ``true``, requests proceed without external processing.

``messageTimeout`` (optional)
    Timeout for an individual message exchange with the ext_proc service.
    If not specified, Envoy's default of 200ms is used. Note that setting
    ``0`` is valid but triggers an immediate timeout on every message,
    effectively failing all ext_proc traffic unless ``failureModeAllow``
    is ``true``. To use no timeout, omit this field entirely.

Example with processing mode and timeout:

.. code-block:: yaml

    apiVersion: cilium.io/v2alpha1
    kind: CiliumEnvoyExtProcFilter
    metadata:
      name: my-ext-proc
    spec:
      backendRef:
        name: ext-proc-service
        port: 4317
      failureModeAllow: true
      messageTimeout: 500ms
      processingMode:
        requestHeaderMode: SEND
        responseHeaderMode: SKIP
        requestBodyMode: BUFFERED
        responseBodyMode: NONE
