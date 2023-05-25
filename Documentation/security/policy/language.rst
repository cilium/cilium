.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _policy_examples:

Layer 3 Examples
================

The layer 3 policy establishes the base connectivity rules regarding which endpoints
can talk to each other. Layer 3 policies can be specified using the following methods:

* `Labels based`: This is used to describe the relationship if both endpoints
  are managed by Cilium and are thus assigned labels. The big advantage of this
  method is that IP addresses are not encoded into the policies and the policy is
  completely decoupled from the addressing.

* `Services based`: This is an intermediate form between Labels and CIDR and
  makes use of the services concept in the orchestration system. A good example
  of this is the Kubernetes concept of Service endpoints which are
  automatically maintained to contain all backend IP addresses of a service.
  This allows to avoid hardcoding IP addresses into the policy even if the
  destination endpoint is not controlled by Cilium.

* `Entities based`: Entities are used to describe remote peers which can be
  categorized without knowing their IP addresses. This includes connectivity
  to the local host serving the endpoints or all connectivity to outside of
  the cluster.

* `CIDR based`: This is used to describe the relationship to or from external
  services if the remote peer is not an endpoint. This requires to hardcode either
  IP addresses or subnets into the policies. This construct should be used as a
  last resort as it requires stable IP or subnet assignments.

* `DNS based`: Selects remote, non-cluster, peers using DNS names converted to
  IPs via DNS lookups. It shares all limitations of the `CIDR based` rules
  above. DNS information is acquired by routing DNS traffic via a proxy.
  DNS TTLs are respected.

.. _Labels based:

Labels Based
------------

Label-based L3 policy is used to establish policy between endpoints inside the
cluster managed by Cilium. Label-based L3 policies are defined by using an
`EndpointSelector` inside a rule to choose what kind of traffic that can be
received (on ingress), or sent (on egress). An empty `EndpointSelector` allows
all traffic. The examples below demonstrate this in further detail.

.. note:: **Kubernetes:** See section :ref:`k8s_namespaces` for details on how
	  the `EndpointSelector` applies in a Kubernetes environment with
	  regard to namespaces.

Ingress
~~~~~~~

An endpoint is allowed to receive traffic from another endpoint if at least one
ingress rule exists which selects the destination endpoint with the
`EndpointSelector` in the ``endpointSelector`` field. To restrict traffic upon
ingress to the selected endpoint, the rule selects the source endpoint with the
`EndpointSelector` in the ``fromEndpoints`` field.

Simple Ingress Allow
~~~~~~~~~~~~~~~~~~~~

The following example illustrates how to use a simple ingress rule to allow
communication from endpoints with the label ``role=frontend`` to endpoints with
the label ``role=backend``.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/simple/l3.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/simple/l3.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/simple/l3.json


Ingress Allow All Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~

An empty `EndpointSelector` will select all endpoints, thus writing a rule that will allow
all ingress traffic to an endpoint may be done as follows:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/ingress-allow-all/ingress-allow-all.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/ingress-allow-all/ingress-allow-all.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/ingress-allow-all/ingress-allow-all.json

Note that while the above examples allow all ingress traffic to an endpoint, this does not
mean that all endpoints are allowed to send traffic to this endpoint per their policies.
In other words, policy must be configured on both sides (sender and receiver).

Egress
~~~~~~

An endpoint is allowed to send traffic to another endpoint if at least one
egress rule exists which selects the destination endpoint with the
`EndpointSelector` in the ``endpointSelector`` field. To restrict traffic upon
egress to the selected endpoint, the rule selects the destination endpoint with
the `EndpointSelector` in the ``toEndpoints`` field.

Simple Egress Allow
~~~~~~~~~~~~~~~~~~~~

The following example illustrates how to use a simple egress rule to allow
communication to endpoints with the label ``role=backend`` from endpoints with
the label ``role=frontend``.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/simple/l3_egress.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/simple/l3_egress.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/simple/l3_egress.json


Egress Allow All Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~

An empty `EndpointSelector` will select all egress endpoints from an endpoint
based on the `CiliumNetworkPolicy` namespace (``default`` by default). The
following rule allows all egress traffic from endpoints with the label
``role=frontend`` to all other endpoints in the same namespace:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/egress-allow-all/egress-allow-all.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/egress-allow-all/egress-allow-all.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/egress-allow-all/egress-allow-all.json


Note that while the above examples allow all egress traffic from an endpoint, the receivers
of the egress traffic may have ingress rules that deny the traffic. In other words,
policy must be configured on both sides (sender and receiver).

Ingress/Egress Default Deny
~~~~~~~~~~~~~~~~~~~~~~~~~~~

An endpoint can be put into the default deny mode at ingress or egress if a
rule selects the endpoint and contains the respective rule section ingress or
egress.

.. note:: Any rule selecting the endpoint will have this effect, this example
          illustrates how to put an endpoint into default deny mode without
          whitelisting other peers at the same time.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/egress-default-deny/egress-default-deny.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/egress-default-deny/egress-default-deny.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/egress-default-deny/egress-default-deny.json

Additional Label Requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is often required to apply the principle of *separation of concern* when defining
policies. For this reason, an additional construct exists which allows to establish
base requirements for any connectivity to happen.

For this purpose, the ``fromRequires`` field can be used to establish label
requirements which serve as a foundation for any ``fromEndpoints``
relationship.  ``fromRequires`` is a list of additional constraints which must
be met in order for the selected endpoints to be reachable. These additional
constraints do not grant access privileges by themselves, so to allow traffic
there must also be rules which match ``fromEndpoints``. The same applies for
egress policies, with ``toRequires`` and ``toEndpoints``.

The purpose of this rule is to allow establishing base requirements such as, any
endpoint in ``env=prod`` can only be accessed if the source endpoint also carries
the label ``env=prod``.

This example shows how to require every endpoint with the label ``env=prod`` to
be only accessible if the source endpoint also has the label ``env=prod``.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/requires/requires.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/requires/requires.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/requires/requires.json

This ``fromRequires`` rule doesn't allow anything on its own and needs to be
combined with other rules to allow traffic. For example, when combined with the
example policy below, the endpoint with label ``env=prod`` will become
accessible from endpoints that have both labels ``env=prod`` and
``role=frontend``.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/requires/endpoints.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/requires/endpoints.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/requires/endpoints.json

.. _Services based:

Services based
--------------

Traffic from pods to services running in your cluster can be allowed via
``toServices`` statements in Egress rules. Currently Kubernetes
`Services without a Selector
<https://kubernetes.io/docs/concepts/services-networking/service/#services-without-selectors>`_
are supported when defined by their name and namespace or label selector.
For services backed by pods, use `labels based` rules on the backend pod labels.

This example shows how to allow all endpoints with the label ``id=app2``
to talk to all endpoints of kubernetes service ``myservice`` in kubernetes
namespace ``default``.

.. note::

	These rules will only take effect on Kubernetes services without a
	selector.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/service/service.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/service/service.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/service/service.json

This example shows how to allow all endpoints with the label ``id=app2``
to talk to all endpoints of all kubernetes headless services which
have ``head:none`` set as the label.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/service/service-labels.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/service/service-labels.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/service/service-labels.json

Limitations
~~~~~~~~~~~

``toServices`` statements cannot be combined with ``toPorts`` statements in the
same rule.

.. _Entities based:

Entities Based
--------------

``fromEntities`` is used to describe the entities that can access the selected
endpoints. ``toEntities`` is used to describe the entities that can be accessed
by the selected endpoints.

The following entities are defined:

host
    The host entity includes the local host. This also includes all
    containers running in host networking mode on the local host.
remote-node
    Any node in any of the connected clusters other than the local host. This
    also includes all containers running in host-networking mode on remote
    nodes. (Requires the option ``enable-remote-node-identity`` to be enabled)
kube-apiserver
    The kube-apiserver entity represents the kube-apiserver in a Kubernetes
    cluster. This entity represents both deployments of the kube-apiserver:
    within the cluster and outside of the cluster.
ingress
    The ingress entity represents the Cilium Envoy instance that handles ingress
    L7 traffic. Be aware that this also applies for pod-to-pod traffic within
    the same cluster when using ingress endpoints (also known as *hairpinning*).
cluster
    Cluster is the logical group of all network endpoints inside of the local
    cluster. This includes all Cilium-managed endpoints of the local cluster,
    unmanaged endpoints in the local cluster, as well as the host,
    remote-node, and init identities.
init
    The init entity contains all endpoints in bootstrap phase for which the
    security identity has not been resolved yet. This is typically only
    observed in non-Kubernetes environments. See section
    :ref:`endpoint_lifecycle` for details.
health
    The health entity represents the health endpoints, used to check cluster
    connectivity health. Each node managed by Cilium hosts a health endpoint.
    See `cluster_connectivity_health` for details on health checks.
unmanaged
    The unmanaged entity represents endpoints not managed by Cilium. Unmanaged
    endpoints are considered part of the cluster and are included in the
    cluster entity.
world
    The world entity corresponds to all endpoints outside of the cluster.
    Allowing to world is identical to allowing to CIDR 0.0.0.0/0. An alternative
    to allowing from and to world is to define fine grained DNS or CIDR based
    policies.
all
    The all entity represents the combination of all known clusters as well
    world and whitelists all communication.

.. versionadded:: future
   Allowing users to define custom entities is on the roadmap but has not been
   implemented yet (see :gh-issue:`3553`).

Access to/from local host
~~~~~~~~~~~~~~~~~~~~~~~~~

Allow all endpoints with the label ``env=dev`` to access the host that is
serving the particular endpoint.

.. note:: Kubernetes will automatically allow all communication from the
	  local host of all local endpoints. You can run the agent with the
	  option ``--allow-localhost=policy`` to disable this behavior which
	  will give you control over this via policy.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/entities/host.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/entities/host.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/entities/host.json

.. _policy-remote-node:

Access to/from all nodes in the cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Allow all endpoints with the label ``env=dev`` to receive traffic from any host
in the cluster that Cilium is running on.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/entities/nodes.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/entities/nodes.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/entities/nodes.json

Access to/from outside cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example shows how to enable access from outside of the cluster to all
endpoints that have the label ``role=public``.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/entities/world.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/entities/world.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/entities/world.json

.. _policy_cidr:
.. _CIDR based:

IP/CIDR based
-------------

CIDR policies are used to define policies to and from endpoints which are not
managed by Cilium and thus do not have labels associated with them. These are
typically external services, VMs or metal machines running in particular
subnets. CIDR policy can also be used to limit access to external services, for
example to limit external access to a particular IP range. CIDR policies can
be applied at ingress or egress.

CIDR rules apply if Cilium cannot map the source or destination to an identity
derived from endpoint labels, ie the `reserved_labels`. For example, CIDR rules
will apply to traffic where one side of the connection is:

* A network endpoint outside the cluster
* The host network namespace where the pod is running.
* Within the cluster prefix but the IP's networking is not provided by Cilium.

Conversely, CIDR rules do not apply to traffic where both sides of the
connection are either managed by Cilium or use an IP belonging to a node in the
cluster (including host networking pods). This traffic may be allowed using
labels, services or entities -based policies as described above.

Ingress
~~~~~~~

fromCIDR
  List of source prefixes/CIDRs that are allowed to talk to all endpoints
  selected by the ``endpointSelector``.

fromCIDRSet
  List of source prefixes/CIDRs that are allowed to talk to all endpoints
  selected by the ``endpointSelector``, along with an optional list of
  prefixes/CIDRs per source prefix/CIDR that are subnets of the source
  prefix/CIDR from which communication is not allowed.

Egress
~~~~~~

toCIDR
  List of destination prefixes/CIDRs that endpoints selected by
  ``endpointSelector`` are allowed to talk to. Note that endpoints which are
  selected by a ``fromEndpoints`` are automatically allowed to reply back to
  the respective destination endpoints.

toCIDRSet
  List of destination prefixes/CIDRs that are allowed to talk to all endpoints
  selected by the ``endpointSelector``, along with an optional list of
  prefixes/CIDRs per source prefix/CIDR that are subnets of the destination
  prefix/CIDR to which communication is not allowed.

Allow to external CIDR block
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example shows how to allow all endpoints with the label ``app=myService``
to talk to the external IP ``20.1.1.1``, as well as the CIDR prefix ``10.0.0.0/8``,
but not CIDR prefix ``10.96.0.0/12``

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/cidr/cidr.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/cidr/cidr.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/cidr/cidr.json

.. _DNS based:

DNS based
---------

DNS policies are used to define Layer 3 policies to endpoints that are not
managed by Cilium, but have DNS queryable domain names. The IP addresses
provided in DNS responses are allowed by Cilium in a similar manner to IPs in
`CIDR based`_ policies. They are an alternative when the remote IPs may change
or are not know a priori, or when DNS is more convenient. To enforce policy on
DNS requests themselves, see `Layer 7 Examples`_.

IP information is captured from DNS responses per-Endpoint via a `DNS Proxy`_.
An L3 `CIDR based`_ rule is generated for every ``toFQDNs``
rule and applies to the same endpoints. The IP information is selected for
insertion by ``matchName`` or ``matchPattern`` rules, and is collected from all
DNS responses seen by Cilium on the node. Multiple selectors may be included in
a single egress rule. See :ref:`DNS Obtaining Data` for information on
collecting this IP data.

.. note:: The DNS Proxy is provided in each Cilium agent.
   As a result, DNS requests targeted by policies depend on the availability
   of the Cilium agent pod.
   This includes DNS policies as well as :ref:`proxy_visibility` annotations.

``toFQDNs`` egress rules cannot contain any other L3 rules, such as
``toEndpoints`` (under `Labels Based`_) and ``toCIDRs`` (under `CIDR Based`_).
They may contain L4/L7 rules, such as ``toPorts`` (see `Layer 4 Examples`_)
with, optionally, ``HTTP`` and ``Kafka`` sections (see `Layer 7 Examples`_).

.. note:: DNS based rules are intended for external connections and behave
          similarly to `CIDR based`_ rules. See `Services based`_ and
          `Labels based`_ for cluster-internal traffic.

IPs to be allowed are selected via:

``toFQDNs.matchName``
  Inserts IPs of domains that match ``matchName`` exactly. Multiple distinct
  names may be included in separate ``matchName`` entries and IPs for domains
  that match any ``matchName`` will be inserted.

``toFQDNs.matchPattern``
  Inserts IPs of domains that match the pattern in ``matchPattern``, accounting
  for wildcards. Patterns are composed of literal characters that are allowed
  in domain names: a-z, 0-9, ``.`` and ``-``.

  ``*`` is allowed as a wildcard with a number of convenience behaviors:

  * ``*`` within a domain allows 0 or more valid DNS characters, except for the
    ``.`` separator. ``*.cilium.io`` will match ``sub.cilium.io`` but not
    ``cilium.io`` or ``sub.sub.cilium.io``. ``part*ial.com`` will match ``partial.com`` and
    ``part-extra-ial.com``.
  * ``*`` alone matches all names, and inserts all cached DNS IPs into this
    rule.

The example below allows all DNS traffic on port 53 to the DNS service and
intercepts it via the `DNS Proxy`_. If using a non-standard DNS port for
a DNS application behind a Kubernetes service, the port must match the backend
port. When the application makes a request for my-remote-service.com, Cilium
learns the IP address and will allow traffic due to the match on the name under
the ``toFQDNs.matchName`` rule.

Example
~~~~~~~

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/fqdn/fqdn.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l3/fqdn/fqdn.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/fqdn/fqdn.json


Managing Short-Lived Connections & Maximum IPs per FQDN/endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Many short-lived connections can grow the number of IPs mapping to an FQDN
quickly. In order to limit the number of IP addresses that map a particular
FQDN, each FQDN has a per-endpoint max capacity of IPs that will be retained
(default: 50). Once this limit is exceeded, the oldest IP entries are
automatically expired from the cache. This capacity can be changed using the
``--tofqdns-endpoint-max-ip-per-hostname`` option.

As with long-lived connections above, live connections are not expired until
they terminate. It is safe to mix long- and short-lived connections from the
same Pod. IPs above the limit described above will only be removed if unused by
a connection.



.. _l4_policy:

Layer 4 Examples
================

Limit ingress/egress ports
--------------------------

Layer 4 policy can be specified in addition to layer 3 policies or independently.
It restricts the ability of an endpoint to emit and/or receive packets on a
particular port using a particular protocol. If no layer 4 policy is specified
for an endpoint, the endpoint is allowed to send and receive on all layer 4
ports and protocols including ICMP. If any layer 4 policy is specified, then
ICMP will be blocked unless it's related to a connection that is otherwise
allowed by the policy. Layer 4 policies apply to ports after service port
mapping has been applied.

Layer 4 policy can be specified at both ingress and egress using the
``toPorts`` field. The ``toPorts`` field takes a ``PortProtocol`` structure
which is defined as follows:

.. code-block:: go

        // PortProtocol specifies an L4 port with an optional transport protocol
        type PortProtocol struct {
                // Port is an L4 port number. For now the string will be strictly
                // parsed as a single uint16. In the future, this field may support
                // ranges in the form "1024-2048"
                Port string `json:"port"`

                // Protocol is the L4 protocol. If omitted or empty, any protocol
                // matches. Accepted values: "TCP", "UDP", ""/"ANY"
                //
                // Matching on ICMP is not supported.
                //
                // +optional
                Protocol string `json:"protocol,omitempty"`
        }

Example (L4)
~~~~~~~~~~~~

The following rule limits all endpoints with the label ``app=myService`` to
only be able to emit packets using TCP on port 80, to any layer 3 destination:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l4/l4.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l4/l4.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l4/l4.json

Labels-dependent Layer 4 rule
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example enables all endpoints with the label ``role=frontend`` to
communicate with all endpoints with the label ``role=backend``, but they must
communicate using TCP on port 80. Endpoints with other labels will not be
able to communicate with the endpoints with the label ``role=backend``, and
endpoints with the label ``role=frontend`` will not be able to communicate with
``role=backend`` on ports other than 80.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l4/l3_l4_combined.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l4/l3_l4_combined.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l4/l3_l4_combined.json

CIDR-dependent Layer 4 Rule
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example enables all endpoints with the label ``role=crawler`` to
communicate with all remote destinations inside the CIDR ``192.0.2.0/24``, but
they must communicate using TCP on port 80. The policy does not allow Endpoints
without the label ``role=crawler`` to communicate with destinations in the CIDR
``192.0.2.0/24``. Furthermore, endpoints with the label ``role=crawler`` will
not be able to communicate with destinations in the CIDR ``192.0.2.0/24`` on
ports other than port 80.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l4/cidr_l4_combined.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l4/cidr_l4_combined.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l4/cidr_l4_combined.json

Limit ICMP/ICMPv6 types
-----------------------

ICMP policy can be specified in addition to layer 3 policies or independently.
It restricts the ability of an endpoint to emit and/or receive packets on a
particular ICMP/ICMPv6 type (currently ICMP/ICMPv6 code is not supported).
If any ICMP policy is specified, layer 4 and ICMP communication will be blocked
unless it's related to a connection that is otherwise allowed by the policy.

ICMP policy can be specified at both ingress and egress using the
``icmps`` field. The ``icmps`` field takes a ``ICMPField`` structure
which is defined as follows:

.. code-block:: go

        // ICMPField is a ICMP field.
        type ICMPField struct {
        	// Family is a IP address version.
        	// Currently, we support `IPv4` and `IPv6`.
        	// `IPv4` is set as default.
        	//
        	// +default=IPv4
        	// +optional
        	Family string `json:"family,omitempty"`

        	// Type is a ICMP-type.
        	// It should be 0-255 (8bit).
        	Type uint8 `json:"type"`
        }

Example (ICMP/ICMPv6)
~~~~~~~~~~~~~~~~~~~~~

The following rule limits all endpoints with the label ``app=myService`` to
only be able to emit packets using ICMP with type 8 and ICMPv6 with type 128,
to any layer 3 destination:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l4/icmp.yaml
           :language: yaml

     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l4/icmp.json
           :language: json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l4/icmp.json
           :language: json



.. _l7_policy:

Layer 7 Examples
================

Layer 7 policy rules are embedded into `l4_policy` rules and can be specified
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

.. note:: There is currently a max limit of 40 ports with layer 7 policies per
          endpoint. This might change in the future when support for ranges is
          added.

.. note:: Layer 7 rules are not currently supported in `HostPolicies`, i.e.,
          policies that use :ref:`NodeSelector`.

.. note:: Layer 7 policies --and pod annotations-- result in traffic being
   proxied through an Envoy instance provided in each Cilium agent pod.
   As a result, L7 traffic targeted by policies depend on the availability
   of the Cilium agent pod.
   This includes L7 policies as well as :ref:`proxy_visibility` annotations.

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

Allow GET /public
~~~~~~~~~~~~~~~~~

The following example allows ``GET`` requests to the URL ``/public`` to be
allowed to endpoints with the labels ``env:prod``, but requests to any other
URL, or using another method, will be rejected. Requests on ports other than
port 80 will be dropped.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l7/http/simple/l7.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l7/http/simple/l7.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l7/http/simple/l7.json

All GET /path1 and PUT /path2 when header set
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example limits all endpoints which carry the labels
``app=myService`` to only be able to receive packets on port 80 using TCP.
While communicating on this port, the only API endpoints allowed will be ``GET
/path1``, and ``PUT /path2`` with the HTTP header ``X-My-Header`` set to
``true``:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l7/http/http.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l7/http/http.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l7/http/http.json

.. _kafka_policy:

Kafka (beta)
------------

.. include:: ../../beta.rst

PortRuleKafka is a list of Kafka protocol constraints. All fields are optional,
if all fields are empty or missing, the rule will match all Kafka messages.
There are two ways to specify the Kafka rules. We can choose to specify a
high-level "produce" or "consume" role to a topic or choose to specify more
low-level Kafka protocol specific apiKeys. Writing rules based on Kafka roles
is easier and covers most common use cases, however if more granularity is
needed then users can alternatively write rules using specific apiKeys.

The following fields can be matched on:

Role
  Role is a case-insensitive string which describes a group of API keys
  necessary to perform certain higher-level Kafka operations such as "produce"
  or "consume". A Role automatically expands into all APIKeys required
  to perform the specified higher-level operation.
  The following roles are supported:

    - "produce": Allow producing to the topics specified in the rule.
    - "consume": Allow consuming from the topics specified in the rule.

  This field is incompatible with the APIKey field, i.e APIKey and Role
  cannot both be specified in the same rule.
  If omitted or empty, and if APIKey is not specified, then all keys are
  allowed.

APIKey
  APIKey is a case-insensitive string matched against the key of a request,
  for example "produce", "fetch", "createtopic", "deletetopic". For a more
  extensive list, see the `Kafka protocol reference <https://kafka.apache.org/protocol#protocol_api_keys>`_.
  This field is incompatible with the Role field.

APIVersion
  APIVersion is the version matched against the api version of the Kafka
  message. If set, it must be a string representing a positive integer. If
  omitted or empty, all versions are allowed.

ClientID
  ClientID is the client identifier as provided in the request.

  From Kafka protocol documentation: This is a user supplied identifier for the
  client application. The user can use any identifier they like and it will be
  used when logging errors, monitoring aggregates, etc. For example, one might
  want to monitor not just the requests per second overall, but the number
  coming from each client application (each of which could reside on multiple
  servers). This id acts as a logical grouping across all requests from a
  particular client.

  If omitted or empty, all client identifiers are allowed.

Topic
  Topic is the topic name contained in the message. If a Kafka request contains
  multiple topics, then all topics in the message must be allowed by the policy
  or the message will be rejected.

  This constraint is ignored if the matched request message type does not
  contain any topic. The maximum length of the Topic is 249 characters,
  which must be either ``a-z``, ``A-Z``, ``0-9``, ``-``, ``.`` or ``_``.

  If omitted or empty, all topics are allowed.

Allow producing to topic empire-announce using Role
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l7/kafka/kafka-role.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l7/kafka/kafka-role.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l7/kafka/kafka-role.json

Allow producing to topic empire-announce using apiKeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l7/kafka/kafka.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l7/kafka/kafka.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l7/kafka/kafka.json


.. _dns_discovery:

DNS Policy and IP Discovery
---------------------------

Policy may be applied to DNS traffic, allowing or disallowing specific DNS
query names or patterns of names (other DNS fields, such as query type, are not
considered). This policy is effected via a DNS proxy, which is also used to
collect IPs used to populate L3 `DNS based`_ ``toFQDNs`` rules.

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
`DNS based`_), restricting connections to TCP port 80 in this case.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l7/dns/dns.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l7/dns/dns.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l7/dns/dns.json


.. note:: When applying DNS policy in kubernetes, queries for
          service.namespace.svc.cluster.local. must be explicitly allowed
          with ``matchPattern: *.*.svc.cluster.local.``.

          Similarly, queries that rely on the DNS search list to complete the
          FQDN must be allowed in their entirety. e.g. A query for
          ``servicename`` that succeeds with
          ``servicename.namespace.svc.cluster.local.`` must have the latter
          allowed with ``matchName`` or ``matchPattern``. See `Alpine/musl deployments and DNS Refused`_.

.. _DNS Obtaining Data:

Obtaining DNS Data for use by ``toFQDNs``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
IPs are obtained via intercepting DNS requests with a proxy or DNS polling, and
matching names are inserted irrespective of how the data is obtained. These IPs
can be selected with ``toFQDN`` rules. DNS responses are cached within Cilium
agent respecting TTL.

.. _DNS Proxy:

DNS Proxy 
"""""""""
  A DNS Proxy intercepts egress DNS traffic and records IPs seen in the
  responses. This interception is, itself, a separate policy rule governing the
  DNS requests, and must be specified separately. For details on how to enforce
  policy on DNS requests and configuring the DNS proxy, see `Layer 7
  Examples`_.

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

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l7/dns/dns-visibility.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../../examples/policies/l7/dns/dns-visibility.json

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l7/dns/dns-visibility.json

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


.. _deny_policies:

Deny Policies
=============

Deny policies, available and enabled by default since Cilium 1.9, allows to
explicitly restrict certain traffic to and from a Pod.

Deny policies take precedence over allow policies, regardless of whether they
are a Cilium Network Policy, a Clusterwide Cilium Network Policy or even a
Kubernetes Network Policy.

Similarly to "allow" policies, Pods will enter default-deny mode as soon a
single policy selects it.

If multiple allow and deny policies are applied to the same pod, the following
table represents the expected enforcement for that Pod:

+--------------------------------------------------------------------------------------------+
| **Set of Ingress Policies Deployed to Server Pod**                                         |
+---------------------+-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 7 (HTTP)        | ✓       | ✓       | ✓      | ✓      |        |
|                     +-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 4 (80/TCP)      | ✓       | ✓       | ✓      | ✓      |        |
| **Allow Policies**  +-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 4 (81/TCP)      | ✓       | ✓       | ✓      | ✓      |        |
|                     +-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 3 (Pod: Client) | ✓       | ✓       | ✓      | ✓      |        |
+---------------------+-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 4 (80/TCP)      |         | ✓       |        | ✓      | ✓      |
| **Deny Policies**   +-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 3 (Pod: Client) |         |         | ✓      | ✓      |        |
+---------------------+-----------------------+---------+---------+--------+--------+--------+
| **Result for Traffic Connections (Allowed / Denied)**                                      |
+---------------------+-----------------------+---------+---------+--------+--------+--------+
|                     | curl server:81        | Allowed | Allowed | Denied | Denied | Denied |
|                     +-----------------------+---------+---------+--------+--------+--------+
| **Client → Server** | curl server:80        | Allowed | Denied  | Denied | Denied | Denied |
|                     +-----------------------+---------+---------+--------+--------+--------+
|                     | ping server           | Allowed | Allowed | Denied | Denied | Denied |
+---------------------+-----------------------+---------+---------+--------+--------+--------+

If we pick the second column in the above table, the bottom section shows the
forwarding behaviour for a policy that selects curl or ping traffic between the
client and server:

* Curl to port 81 is allowed because there is an allow policy on port 81, and
  no deny policy on that port;
* Curl to port 80 is denied because there is a deny policy on that port;
* Ping to the server is allowed because there is a Layer 3 allow policy and no deny.

The following policy will deny ingress from "world" on all namespaces on all
Pods managed by Cilium. Existing inter-cluster policies will still be allowed
as this policy is allowing traffic from everywhere except from "world".

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/l3/entities/from_world_deny.yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/l3/entities/from_world_deny.yaml

Deny policies do not support: policy enforcement at L7, i.e., specifically
denying an URL and ``toFQDNs``, i.e., specifically denying traffic to a specific
domain name.


Known issues
------------

There is currently a known issue (:gh-issue:`24502`) that makes the ``kube-apiserver``
entity unreliable. Until this is resolved, it is recommended to grant access to the apiserver
by CIDR or by the special ``world`` entity.

Previous limitations and known issues
-------------------------------------

For Cilium versions prior to 1.14 deny-policies for peers outside the cluster
sometimes did not work because of :gh-issue:`15198`.  Make sure that you are
using version 1.14 or later if you are relying on deny policies to manage
external traffic to your cluster.

.. _HostPolicies:

Host Policies
=============

Host policies take the form of a `CiliumClusterwideNetworkPolicy` with a
:ref:`NodeSelector` instead of an `EndpointSelector`. Host policies can have
layer 3 and layer 4 rules on both ingress and egress. They cannot have layer
7 rules.

Host policies apply to all the nodes selected by their :ref:`NodeSelector`. In
each selected node, they apply only to the host namespace, including
host-networking pods. They therefore don't apply to communications between
non-host-networking pods and locations outside of the cluster.

Installation of Host Policies requires the addition of the following ``helm``
flags when installing Cilium:

* ``--set devices='{interface}'`` where ``interface`` refers to the
  network device Cilium is configured on such as ``eth0``. Omitting this option
  leads Cilium to auto-detect what interface the host firewall applies to.
* ``--set hostFirewall.enabled=true``

The following policy will allow ingress traffic for any node with the label
``type=ingress-worker`` on TCP ports 22, 6443 (kube-apiserver), 2379 (etcd) and 4240
(health checks), as well as UDP port 8472 (VXLAN).

Replace the ``port:`` value with ports used in your environment.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../../examples/policies/host/lock-down-ingress.yaml

.. only:: epub or latex

        .. literalinclude:: ../../../examples/policies/host/lock-down-ingress.yaml

Troubleshooting Host Policies
-----------------------------

If you're having troubles with Host Policies please ensure the ``helm`` options
listed above were applied during installation. To verify that your policy has
been applied, you can run ``kubectl get CiliumClusterwideNetworkPolicy -o yaml``
to validate the policy was accepted.

If policies don't seem to be applied to your nodes, verify the ``nodeSelector``
is labeled correctly in your environment. In the example configuration, you can
run ``kubectl get nodes -o wide|grep type=ingress-worker`` to verify labels
match the policy.

You can verify the policy was applied by running ``kubectl exec -n $CILIUM_NAMESPACE cilium-xxxx -- cilium policy get``
for the Cilium agent pod. Verify that the host is selected by the policy using
``cilium endpoint list`` and look for the endpoint with ``reserved:host`` as the
label and ensure that policy is enabled in the selected direction. Ensure the
traffic is arriving on the device visible on the ``NodePort`` field of the
``cilium status list`` output. Use ``cilium monitor`` with ``--related-to`` and
the endpoint ID of the ``reserved:host`` endpoint to view traffic.
