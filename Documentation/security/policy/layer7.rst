.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _l7_policy:

Layer 7 Policies
================

Layer 7 policy rules are embedded into Layer 4 rules and can be specified
for ingress and egress. ``L7Rules`` structure is a base type containing an
enumeration of protocol specific fields.

.. code-block:: go

        // L7Rules is a union of port level rule types. Mixing of different port
        // level rule types is disallowed, so exactly one of the following must be set.
        // If none are specified, then no additional port level rules are applied.
        type L7Rules struct {
                // HTTP specific rules.
                //
                // +optional
                HTTP []PortRuleHTTP `json:"http,omitempty"`

                // Kafka-specific rules.
                //
                // +optional
                Kafka []PortRuleKafka `json:"kafka,omitempty"`

                // DNS-specific rules.
                //
                // +optional
                DNS []PortRuleDNS `json:"dns,omitempty"`
        }

The structure is implemented as a union, i.e. only one member field can be used
per port. If multiple ``toPorts`` rules with identical ``PortProtocol`` select
an overlapping list of endpoints, then the layer 7 rules are combined together
if they are of the same type. If the type differs, the policy is rejected.

Each member consists of a list of application protocol rules. A layer 7
request is permitted if at least one of the rules matches. If no rules are
specified, then all traffic is permitted.

If a layer 4 rule is specified in the policy, and a similar layer 4 rule
with layer 7 rules is also specified, then the layer 7 portions of the
latter rule will have no effect.

.. note:: Unlike layer 3 and layer 4 policies, violation of layer 7 rules does
          not result in packet drops. Instead, if possible, an application
          protocol specific access denied message is crafted and returned, e.g.
          an *HTTP 403 access denied* is sent back for HTTP requests which
          violate the policy, or a *DNS REFUSED* response for DNS requests.

.. note:: Layer 7 rules support port ranges, except for DNS rules.

.. note:: In `HostPolicies`, i.e. policies that use :ref:`NodeSelector`,
          only DNS layer 7 rules are currently functional.
          Other types of layer 7 rules cannot be specified in `HostPolicies`.

          Host layer 7 DNS policies are a beta feature.
          Please provide feedback and file a GitHub issue if you experience any problems.

.. note:: Layer 7 policies will proxy traffic through a node-local :ref:`envoy`
          instance, which will either be deployed as a DaemonSet or embedded in the agent pod.
          When Envoy is embedded in the agent pod, Layer 7 traffic targeted by policies
          will therefore depend on the availability of the Cilium agent pod.

.. note:: L7 policies for SNATed IPv6 traffic (e.g., pod-to-world) require a kernel with the `fix <https://patchwork.kernel.org/project/netdevbpf/patch/20250318161516.3791383-1-maxim@isovalent.com/>`__ applied.
          The stable kernel versions with the fix are 6.14.1, 6.12.22, 6.6.86, 6.1.133, 5.15.180, 5.10.236. See :gh-issue:`37932` for the reference.

HTTP
----

The following fields can be matched on:

Path
  Path is an extended POSIX regex matched against the path of a request.
  Currently it can contain characters disallowed from the conventional "path"
  part of a URL as defined by RFC 3986. Paths must begin with a ``/``. If
  omitted or empty, all paths are all allowed.

Method
  Method is an extended POSIX regex matched against the method of a request,
  e.g. ``GET``, ``POST``, ``PUT``, ``PATCH``, ``DELETE``, ...  If omitted or
  empty, all methods are allowed.

Host
  Host is an extended POSIX regex matched against the host header of a request,
  e.g. ``foo.com``. If omitted or empty, the value of the host header is
  ignored.

Headers
  Headers is a list of HTTP headers which must be present in the request. If
  omitted or empty, requests are allowed regardless of headers present.

  It's also possible to do some more advanced header matching against header
  values. ``HeaderMatches`` is a list of HTTP headers which must be present and
  match against the given values. Mismatch field can be used to specify what
  to do when there is no match.

Allow GET /public
~~~~~~~~~~~~~~~~~

The following example allows ``GET`` requests to the URL ``/public`` from the
endpoints with the labels ``env=prod`` to endpoints with the labels
``app=service``, but requests to any other URL, or using another method, will
be rejected. Requests on ports other than port 80 will be dropped.

.. literalinclude:: ../../../examples/policies/l7/http/simple/l7.yaml
  :language: yaml

All GET /path1 and PUT /path2 when header set
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example limits all endpoints which carry the labels
``app=myService`` to only be able to receive packets on port 80 using TCP.
While communicating on this port, the only API endpoints allowed will be ``GET
/path1``, and ``PUT /path2`` with the HTTP header ``X-My-Header`` set to
``true``:

.. literalinclude:: ../../../examples/policies/l7/http/http.yaml
  :language: yaml

.. _dns_discovery:

DNS Policy and IP Discovery
---------------------------

Policy may be applied to DNS traffic, allowing or disallowing specific DNS
query names or patterns of names (other DNS fields, such as query type, are not
considered). This policy is effected via a `DNS Proxy`, which is also used to
collect IPs used to populate L3 `DNS based` ``toFQDNs`` rules.

.. note::  While Layer 7 DNS policy can be applied without any other Layer 3
           rules, the presence of a Layer 7 rule (with its Layer 3 and 4
           components) will block other traffic.

DNS policy may be applied via:

``matchName``
  Allows queries for domains that match ``matchName`` exactly. Multiple
  distinct names may be included in separate ``matchName`` entries and queries
  for domains that match any ``matchName`` will be allowed.

``matchPattern``
  Allows queries for domains that match the pattern in ``matchPattern``,
  accounting for wildcards. Patterns are composed of literal characters that
  that are allowed in domain names: a-z, 0-9, ``.`` and ``-``.

  ``*`` is allowed as a wildcard with a number of convenience behaviors:

  * ``*`` within a domain allows 0 or more valid DNS characters, except for the
    ``.`` separator. ``*.cilium.io`` will match ``sub.cilium.io`` but not
    ``cilium.io``. ``part*ial.com`` will match ``partial.com`` and
    ``part-extra-ial.com``.
  * ``*`` alone matches all names, and inserts all IPs in DNS responses into
    the cilium-agent DNS cache.

In this example, L7 DNS policy allows queries for ``cilium.io``, any subdomains
of ``cilium.io``, and any subdomains of ``api.cilium.io``. No other DNS queries
will be allowed.

The separate L3 ``toFQDNs`` egress rule allows connections to any IPs returned
in DNS queries for ``cilium.io``, ``sub.cilium.io``, ``service1.api.cilium.io``
and any matches of ``special*service.api.cilium.io``, such as
``special-region1-service.api.cilium.io`` but not
``region1-service.api.cilium.io``. DNS queries to ``anothersub.cilium.io`` are
allowed but connections to the returned IPs are not, as there is no L3
``toFQDNs`` rule selecting them. L4 and L7 policy may also be applied (see
`DNS based`), restricting connections to TCP port 80 in this case.

.. literalinclude:: ../../../examples/policies/l7/dns/dns.yaml
  :language: yaml

.. note:: When applying DNS policy in kubernetes, queries for
          service.namespace.svc.cluster.local. must be explicitly allowed
          with ``matchPattern: *.*.svc.cluster.local.``.

          Similarly, queries that rely on the DNS search list to complete the
          FQDN must be allowed in their entirety. e.g. A query for
          ``servicename`` that succeeds with
          ``servicename.namespace.svc.cluster.local.`` must have the latter
          allowed with ``matchName`` or ``matchPattern``. See `Alpine/musl deployments and DNS Refused`_.

.. note:: DNS policies do not support port ranges.

.. _DNS Obtaining Data:

Obtaining DNS Data for use by ``toFQDNs``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
IPs are obtained via intercepting DNS requests with a proxy. These IPs can be
selected with ``toFQDN`` rules. DNS responses are cached within Cilium agent
respecting TTL.

.. _DNS Proxy:

DNS Proxy
~~~~~~~~~
A DNS Proxy in the agent intercepts egress DNS traffic and records IPs seen
in the responses. This interception is, itself, a separate policy rule governing
DNS requests, and must be specified separately. For details on how to enforce
policy on DNS requests and configuring the DNS proxy, see `Layer 7 Policies`_.

Only IPs in intercepted DNS responses to an application will be allowed in
the Cilium policy rules. For a given domain name, IPs from responses to all
pods managed by a Cilium instance are allowed by policy (respecting TTLs).
This ensures that allowed IPs are consistent with those returned to
applications. The DNS Proxy is the only method to allow IPs from responses
allowed by wildcard L7 DNS ``matchPattern`` rules for use in ``toFQDNs``
rules.

The following example obtains DNS data by interception without blocking any
DNS requests. It allows L3 connections to ``cilium.io``, ``sub.cilium.io``
and any subdomains of ``sub.cilium.io``.

.. literalinclude:: ../../../examples/policies/l7/dns/dns-visibility.yaml
  :language: yaml

.. note:: DNS policies do not support port ranges.


Alpine/musl deployments and DNS Refused
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some common container images treat the DNS ``Refused`` response when the `DNS
Proxy`_ rejects a query as a more general failure. This stops traversal of the
search list defined in ``/etc/resolv.conf``. It is common for pods to search by
appending ``.svc.cluster.local.`` to DNS queries. When this occurs, a lookup
for ``cilium.io`` may first be attempted as
``cilium.io.namespace.svc.cluster.local.`` and rejected by the proxy. Instead
of continuing and eventually attempting ``cilium.io.`` alone, the Pod treats
the DNS lookup is treated as failed.

This can be mitigated with the ``--tofqdns-dns-reject-response-code`` option.
The default is ``refused`` but ``nameError`` can be selected, causing the proxy
to return a NXDomain response to refused queries.

A more pod-specific solution is to configure ``ndots`` appropriately for each
Pod, via ``dnsConfig``, so that the search list is not used for DNS lookups
that do not need it. See the `Kubernetes documentation <https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-config>`_
for instructions.
