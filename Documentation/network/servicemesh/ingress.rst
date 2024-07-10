.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress:

**************************
Kubernetes Ingress Support
**************************

Cilium uses the standard `Kubernetes Ingress`_ resource definition, with
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

.. _Kubernetes Ingress: https://kubernetes.io/docs/concepts/services-networking/ingress/

Prerequisites
#############

* Cilium must be configured with NodePort enabled, using
  ``nodePort.enabled=true`` or by enabling the kube-proxy replacement with
  ``kubeProxyReplacement=true``. For more information, see :ref:`kube-proxy
  replacement <kubeproxy-free>`.
* Cilium must be configured with the L7 proxy enabled using ``l7Proxy=true``
  (enabled by default).

.. include:: installation.rst

.. include:: ingress-reference.rst

.. include:: ingress-reference.rst


Ingress Path Types and Precedence
*********************************

The Ingress specification supports three types of paths:

* **Exact** - match the given path exactly.
* **Prefix** - match the URL path prefix split by ``/``. The last path segment must
  match the whole segment - if you configure a Prefix path of ``/foo/bar``,
  ``/foo/bar/baz`` will match, but ``/foo/barbaz`` will not.
* **ImplementationSpecific** - Interpretation of the Path is up to the IngressClass.
  **In Cilium's case, we define ImplementationSpecific to be "Regex"**, so Cilium will
  interpret any given path as a regular expression and program Envoy accordingly.
  Notably, some other implementations have ImplementationSpecific mean "Prefix",
  and in those cases, Cilium will treat the paths differently. (Since a path like
  ``/foo/bar`` contains no regex characters, when it is configured in Envoy as a
  regex, it will function as an ``Exact`` match instead).

When multiple path types are configured on an Ingress object, Cilium will configure
Envoy with the matches in the following order:

#. Exact
#. ImplementationSpecific (that is, regular expression)
#. Prefix
#. The ``/`` Prefix match has special handling and always goes last.

Within each of these path types, the paths are sorted in decreasing order of string
length.

If you do use ImplementationSpecific regex support, be careful with using the
``*`` operator, since it will increase the length of the regex, but may match
another, shorter option.

For example, if you have two ImplementationSpecific paths, ``/impl``, and ``/impl.*``,
the second will be sorted ahead of the first in the generated config. But because
``*`` is in use, the ``/impl`` match will never be hit, as any request to that
path will match the ``/impl.*`` path first.

See the :ref:`Ingress Path Types <gs_ingress_path_types>` for more information.

Supported Ingress Annotations
*****************************

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
   ingress-and-network-policy
   path-types
   grpc
   tls-termination
   tls-default-certificate
