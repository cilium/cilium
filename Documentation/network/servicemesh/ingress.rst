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

Reference
#########

How Cilium Ingress differs from other Ingress controllers
*********************************************************

One of the biggest differences between Cilium Ingress and other Ingress controllers
is how closely tied the implementation is to the CNI. For Cilium, Ingress is part
of the networking stack, and so behaves in a different way to other Ingress
controllers (even other Ingress controllers running in a Cilium cluster).

Other Ingress controllers are generally installed as a Deployment or Daemonset
in the cluster, and exposed via a Loadbalancer Service or similar (which Cilium
can, of course, enable).

Cilium Ingress is exposed with a Loadbalancer or NodePort service, or optionally
can be exposed on the Host network also. But in all of these cases, when traffic
arrives at the Service's port, eBPF code intercepts the traffic and transparently
forwards it to Envoy (using the TPROXY kernel facility).

This affects things like client IP visibility, which works differently for Cilium
Ingress to other Ingress controllers.

It also allows Cilium's Network Policy engine to apply CiliumNetworkPolicy to
traffic bound for and traffic coming from an Ingress.

Ingress and CiliumNetworkPolicy
*******************************

Ingress traffic bound to backend services via Cilium Ingress passes through a
per-node Envoy proxy.

The per-node Envoy proxy has special code that allows it to interact with the
eBPF policy engine, and do policy lookups on traffic. This allows Envoy to be
a Network Policy enforcement point, both for Ingress (and Gateway API) traffic,
and also for east-west traffic via GAMMA or L7 Traffic Management.

However, for Ingress, there's also an additional step. Traffic that arrives at
Envoy *for Ingress or Gateway API* is assigned the special ``ingress`` identity
in Cilium's Policy engine.

Traffic coming from outside the cluster is usually assigned the ``world`` identity
(unless there are IP CIDR policies in the cluster). This means that there are
actually *two* logical Policy enforcement points in Cilium Ingress - before traffic
arrives at the ``ingress`` identity, and after, when it is about to exit the
per-node Envoy.

.. image:: /images/ingress-policy.png
    :align: center

This means that, when applying Network Policy to a cluster, it's important to
ensure that both steps are allowed, and that traffic is allowed from ``world`` to
``ingress``, and from ``ingress`` to identities in the cluster (like the
``productpage`` identity in the image above).

Please see the Ingress and Policy example below for more details.


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
   :header-rows: 1

   * - Name
     - Description
     - Default Value
   * - ``ingress.cilium.io/loadbalancer-mode``
     - | The loadbalancer mode for the ingress.
       | Allows a per ingress override
       | of the default set in the Helm value
       | ``ingressController.loadbalancerMode``.
       | Applicable values are ``dedicated`` and
       | ``shared``.
     - | ``dedicated``
       | (from Helm chart)
   * - ``ingress.cilium.io/service-type``
     - | The Service type for dedicated Ingress.
       | Applicable values are ``LoadBalancer``
       | and ``NodePort``.
     - ``LoadBalancer``
   * - ``ingress.cilium.io/insecure-node-port``
     - | The NodePort to use for the HTTP Ingress.
       | Applicable only if ``ingress.cilium.io/service-type`` is ``NodePort``. If unspecified, a random
       | NodePort will be allocated by kubernetes.
     - unspecified
   * - ``ingress.cilium.io/secure-node-port``
     - | The NodePort to use for the HTTPS Ingress.
       | Applicable only if ``ingress.cilium.io/service-type`` is ``NodePort``. If unspecified, a random
       | NodePort will be allocated by kubernetes.
     - unspecified
   * - ``ingress.cilium.io/tcp-keep-alive``
     - | Enable TCP keep-alive. Applicable values
       | are ``enabled`` and ``disabled``.
     - ``enabled``
   * - ``ingress.cilium.io/tcp-keep-alive-idle``
     - TCP keep-alive idle time (in seconds)
     - ``10``
   * - ``ingress.cilium.io/tcp-keep-alive-probe-interval``
     - TCP keep-alive probe intervals (in seconds)
     - ``5``
   * - ``ingress.cilium.io/tcp-keep-alive-probe-max-failures``
     - TCP keep-alive probe max failures
     - ``10``
   * - ``ingress.cilium.io/websocket``
     - | Enable websocket passthrough support.
       | Applicable values are ``enabled`` and ``disabled``.
     - ``disabled``
   * - ``ingress.cilium.io/tls-passthrough``
     - | Enable TLS Passthrough mode for this Ingress.
       | Applicable values are ``enabled`` and ``disabled``,
       | although boolean-style values will also be
       | accepted.
       |
       | Note that some conditions apply to TLS
       | Passthrough Ingresses, due to how
       | TLS Passthrough works:
       | * A ``host`` field must be set in the Ingress
       | * Default backends are ignored
       | * Rules with paths other than ``/`` are ignored
       | If all the rules in an Ingress are ignored for
       | these reasons, no Envoy config will be generated
       | and the Ingress will have no effect.
       |
       | Note that this annotation is analogous to
       | the ``ssl-passthrough`` on other Ingress
       | controllers.
     - ``disabled``

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
