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
are supported.

By default, annotations with values beginning with:

* ``service.beta.kubernetes.io``
* ``service.kubernetes.io``
* ``cloud.google.com``

will be copied from an Ingress object to the generated LoadBalancer service objects.

This setting is controlled by the Cilium Operator's ``ingress-lb-annotation-prefixes``
config flag, and can be configured in Cilium's Helm ``values.yaml``
using the ``ingressController.ingressLBAnnotationPrefixes`` setting.

Please refer to the `Kubernetes documentation <https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer>`_
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
