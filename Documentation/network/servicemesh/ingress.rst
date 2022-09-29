.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress:

**************************
Kubernetes Ingress Support
**************************

Cilium uses the standard Kubernetes Ingress resource definition, with
an ``ingressClassName`` of ``cilium``. This can be used for path-based
routing and for TLS termination.

.. Note::

    The ingress controller creates a service of LoadBalancer type, so
    your environment will need to support this.

Cilium allows you to specify load balancer mode for the Ingress resource:

- ``dedicated``: The Ingress controller will create a dedicated loadbalancer
  for the Ingress.
- ``shared``: The Ingress controller will use a shared loadbalancer for all
  Ingress resources.

Each load balancer mode has its own benefits and drawbacks. The shared mode saves
resources by sharing a single LoadBalancer config across all Ingress resources in
the cluster, while the dedicated mode can help to avoid potential conflicts (e.g.
path prefix) between resources.

.. Note::

    It is possible to change the load balancer mode for an Ingress resource.
    When the mode is changed, active connections to backends of the Ingress
    may be terminated during the reconfiguration due to a new load balancer
    IP address being assigned to the Ingress resource.

This is a step-by-step guide on how to enable the Ingress Controller in
an existing K8s cluster with Cilium installed.

.. include:: installation.rst

Supported Ingress Annotations
#############################

.. list-table:: 
   :widths: 25 25 50
   :header-rows: 1

   * - Name
     - Description
     - Default Value
   * - ``io.cilium.ingress/loadbalancer-mode``
     - The loadbalancer mode for the ingress. Applicable values are ``dedicated`` and ``shared``.
     - Defaults to Helm option ``ingressController.loadbalancerMode`` value.
   * - ``io.cilium/tcp-keep-alive``
     - Enable TCP keep-alive
     - 1 (enabled)
   * - ``io.cilium/tcp-keep-alive-idle``
     - TCP keep-alive idle time (in seconds)
     - 10s
   * - ``io.cilium/tcp-keep-alive-probe-interval``
     - TCP keep-alive probe intervals (in seconds)
     - 5s
   * - ``io.cilium/tcp-keep-alive-probe-max-failures``
     - TCP keep-alive probe max failures
     - 10
   * - ``io.cilium/websocket``
     - Enable websocket
     - 0 (disabled)

Additionally, cloud-provider specific annotations for the LoadBalancer service
are supported. Please refer to the `Kubernetes documentation <https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer>`_
for more details.

Examples
########

Please refer to one of the below examples on how to use and leverage
Cilium's Ingress features:

.. toctree::
   :maxdepth: 1
   :glob:

   http
   grpc
   tls-termination
