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
routing and for TLS termination. For backwards compatibility, the 
``kubernetes.io/ingress.class`` annotation with value of ``cilium``
is also supported.

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

Prerequisites
#############

* Cilium must be configured with ``kubeProxyReplacement`` as partial
  or strict. Please refer to :ref:`kube-proxy replacement <kubeproxy-free>`
  for more details.
* Cilium must be configured with the L7 proxy enabled using the ``--enable-l7-proxy`` flag (enabled by default).
* The minimum supported Kubernetes version for Ingress is 1.19.

.. include:: installation.rst

Supported Ingress Annotations
#############################

.. list-table:: 
   :widths: 25 25 50
   :header-rows: 1

   * - Name
     - Description
     - Default Value
   * - ``ingress.cilium.io/loadbalancer-mode``
     - The loadbalancer mode for the ingress. Applicable values are ``dedicated`` and ``shared``.
     - Defaults to Helm option ``ingressController.loadbalancerMode`` value.
   * - ``ingress.cilium.io/service-type``
     - The Service type for dedicated Ingress. Applicable values are ``LoadBalancer`` and ``NodePort``.
     - Defaults to ``LoadBalancer`` if unspecified.
   * - ``ingress.cilium.io/insecure-node-port``
     - The NodePort to use for the HTTP Ingress. Applicable only if ``ingress.cilium.io/service-type`` is ``NodePort``.
     - If unspecified, a random NodePort will be allocated by kubernetes.
   * - ``ingress.cilium.io/secure-node-port``
     - The NodePort to use for the HTTPS Ingress. Applicable only if ``ingress.cilium.io/service-type`` is ``NodePort``.
     - If unspecified, a random NodePort will be allocated by kubernetes.
   * - ``ingress.cilium.io/tcp-keep-alive``
     - Enable TCP keep-alive
     - 1 (enabled)
   * - ``ingress.cilium.io/tcp-keep-alive-idle``
     - TCP keep-alive idle time (in seconds)
     - 10s
   * - ``ingress.cilium.io/tcp-keep-alive-probe-interval``
     - TCP keep-alive probe intervals (in seconds)
     - 5s
   * - ``ingress.cilium.io/tcp-keep-alive-probe-max-failures``
     - TCP keep-alive probe max failures
     - 10
   * - ``ingress.cilium.io/websocket``
     - Enable websocket
     - disabled

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
