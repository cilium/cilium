.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_l7_traffic_management:

***************************
L7-Aware Traffic Management
***************************

Cilium provides a way to control L7 traffic via CRDs (e.g. CiliumEnvoyConfig
and CiliumClusterwideEnvoyConfig).

Prerequisites
#############

* Cilium must be configured with ``kubeProxyReplacement`` as partial
  or strict. Please refer to :ref:`kube-proxy replacement <kubeproxy-free>`
  for more details.
* The minimum supported Kubernetes version for Ingress is 1.19.

.. include:: installation.rst

Supported Envoy API Versions
============================

As of now only the Envoy API v3 is supported.

Supported Envoy Extension Resource Types
========================================

Envoy extensions are resource types that may or may not be built in to
an Envoy build. The standard types referred to in Envoy documentation,
such as ``type.googleapis.com/envoy.config.listener.v3.Listener``, and
``type.googleapis.com/envoy.config.route.v3.RouteConfiguration``, are
always available.

Cilium nodes deploy an Envoy image to support Cilium HTTP policy
enforcement and observability. This build of Envoy has been optimized
for the needs of the Cilium Agent and does not contain many of the
Envoy extensions available in the Envoy code base.

To see which Envoy extensions are available, please have a look at
the `Envoy extensions configuration
file <https://github.com/cilium/proxy/blob/master/envoy_build_config/extensions_build_config.bzl>`_.
Only the extensions that have not been commented out with ``#`` are
built in to the Cilium Envoy image. Currently this contains the
following extensions:

- ``envoy.clusters.dynamic_forward_proxy``
- ``envoy.filters.http.dynamic_forward_proxy``
- ``envoy.filters.http.ext_authz``
- ``envoy.filters.http.jwt_authn``
- ``envoy.filters.http.local_ratelimit``
- ``envoy.filters.http.oauth2``
- ``envoy.filters.http.ratelimit``
- ``envoy.filters.http.router``
- ``envoy.filters.http.set_metadata``
- ``envoy.filters.listener.tls_inspector``
- ``envoy.filters.network.connection_limit``
- ``envoy.filters.network.ext_authz``
- ``envoy.filters.network.http_connection_manager``
- ``envoy.filters.network.local_ratelimit``
- ``envoy.filters.network.mongo_proxy``
- ``envoy.filters.network.mysql_proxy``
- ``envoy.filters.network.ratelimit``
- ``envoy.filters.network.tcp_proxy``
- ``envoy.filters.network.sni_cluster``
- ``envoy.filters.network.sni_dynamic_forward_proxy``
- ``envoy.stat_sinks.metrics_service``
- ``envoy.transport_sockets.raw_buffer``
- ``envoy.upstreams.http.http``
- ``envoy.upstreams.http.tcp``

We will evolve the list of built-in extensions based on user
feedback.

Examples
########

Please refer to one of the below examples on how to use and leverage
Cilium's Ingress features:

.. toctree::
   :maxdepth: 1
   :glob:

   envoy-custom-listener
   envoy-traffic-management
   envoy-load-balancing
