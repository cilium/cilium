.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

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
  above. The current implementation simply polls the listed DNS targets without
  regard for TTLs, and allows traffics from IPs listed in the DNS responses.

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

        .. literalinclude:: ../../examples/policies/l3/simple/l3.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/simple/l3.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/simple/l3.json


Ingress Allow All
~~~~~~~~~~~~~~~~~

An empty `EndpointSelector` will select all endpoints, thus writing a rule that will allow
all ingress traffic to an endpoint may be done as follows:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/ingress-allow-all/ingress-allow-all.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/ingress-allow-all/ingress-allow-all.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/ingress-allow-all/ingress-allow-all.json

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

        .. literalinclude:: ../../examples/policies/l3/simple/l3_egress.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/simple/l3_egress.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/simple/l3_egress.json


Egress Allow All
~~~~~~~~~~~~~~~~~

An empty `EndpointSelector` will select all endpoints, thus writing a rule that will allow
all egress traffic from an endpoint may be done as follows:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/egress-allow-all/egress-allow-all.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/egress-allow-all/egress-allow-all.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/egress-allow-all/egress-allow-all.json


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

        .. literalinclude:: ../../examples/policies/l3/egress-default-deny/egress-default-deny.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/egress-default-deny/egress-default-deny.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/egress-default-deny/egress-default-deny.json

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

        .. literalinclude:: ../../examples/policies/l3/requires/requires.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/requires/requires.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/requires/requires.json

.. _Services based:

Services based
--------------

Services running in your cluster can be whitelisted in Egress rules.
Currently Kubernetes `Services without a Selector
<https://kubernetes.io/docs/concepts/services-networking/service/#services-without-selectors>`_
are supported when defined by their name and namespace or label selector.
Future versions of Cilium will support specifying non-Kubernetes services
and Kubernetes services which are backed by pods.

This example shows how to allow all endpoints with the label ``id=app2``
to talk to all endpoints of kubernetes service ``myservice`` in kubernetes
namespace ``default``.

.. note::

	These rules will only take effect on Kubernetes services without a
	selector.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/service/service.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/service/service.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/service/service.json

This example shows how to allow all endpoints with the label ``id=app2``
to talk to all endpoints of all kubernetes headless services which
have ``head:none`` set as the label.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/service/service-labels.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/service/service-labels.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/service/service-labels.json


.. _Entities based:

Entities Based
--------------

``fromEntities`` is used to describe the entities that can access the selected
endpoints. ``toEntities`` is used to describe the entities that can be accessed
by the selected endpoints.

The following entities are defined:

host
    The local host serving the endpoint. On ingress, this also includes
    the host of other Cilium cluster nodes.
world
    All traffic outside of the cluster.
all
    All traffic both within the cluster and outside of the cluster.

.. versionadded:: future
   Allowing users to `define custom identities <https://github.com/cilium/cilium/issues/3553>`_
   is on the roadmap but has not been implemented yet.

Access to/from local host
~~~~~~~~~~~~~~~~~~~~~~~~~

Allow all endpoints with the label ``env=dev`` to access the host that is
serving the particular endpoint.

.. note:: Kubernetes will automatically allow all communication from and to the
	  local host of all local endpoints. You can run the agent with the
	  option ``--allow-localhost=policy`` to disable this behavior which
	  will give you control over this via policy.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/entities/host.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/entities/host.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/entities/host.json


Access to/from outside cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example shows how to enable access from outside of the cluster to all
endpoints that have the label ``role=public``.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/entities/world.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/entities/world.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/entities/world.json

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

.. note::

   When running Cilium on Linux 4.10 or earlier, there are :ref:`cidr_limitations`.

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
  selected by a ``fromEndpoints`` are automatically allowed to talk to their
  respective destination endpoints.

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

        .. literalinclude:: ../../examples/policies/l3/cidr/cidr.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/cidr/cidr.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/cidr/cidr.json

.. _DNS based:

DNS based
---------

``toFQDNs`` simplifies specifying egress policy to IPs of remote, external,
peers. The DNS lookup for each ``matchName`` is done periodically by
``cilium-agent`` and the result is used to regenerate endpoint policy. This
allows tracking changing IPs or sets of IPs that may not be known a priori.
Despite the naming, the ``matchName`` field does not have to be a
fully-qualified domain name. In cases where search domains are configured, the
DNS lookups from ``cilium`` will not be qualified and will utilize the search
list.

The DNS lookups are repeated with an interval of 5 seconds, and are made for
A(IPv4) and AAAA(IPv6) addresses. Should a lookup fail, the most recent IP data
is used instead. An IP change will trigger a regeneration of the ``cilium``
policy for each endpoint, and the updated IPs can be seen in the response from
``cilium policy get``. Each update will also increment the per ``cilium-agent``
policy repository revision.

``toFQDNs`` rules cannot contain any other L3 rules, such as ``toEndpoints``
(under `Labels Based`_) and ``toCIDRs`` (under `CIDR Based`_). They can contain
L4/L7 rules, such as ``toPorts`` (see `Layer 4 Examples`_)  and, optionally,
with ``HTTP`` and ``Kafka`` sections (see `Layer 7 Examples`_).

.. note:: ``toFQDNs`` rules are marked on import with a
          ``cilium-generated:ToFQDN-UUID`` label. This is for internal
          bookkeeping and can be safely ignored.


.. note:: The DNS resolver must be explicitly whitelisted to allow cilium-agent
          to send the DNS polls. This is illustrated in the example below.

Example
~~~~~~~

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/fqdn/fqdn.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/fqdn/fqdn.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/fqdn/fqdn.json

Limitations
~~~~~~~~~~~

The current ``toFQDNs`` implementation is very limited. It may not behave as expected.

#. The DNS polling is done from the ``cilium-agent`` process. This may result
   in different IPs being returned in the DNS response than those seen by an
   endpoint or pod.

#. The IP response is used as-is. For DNS responses that return a new IP on
   every query this may result in a different IP being whitelisted than the one
   used for current connections.

#. The lookups from ``cilium`` follow the configuration of the environment it
   is in via ``/etc/resolv.conf``. When running as a pod, the contents of
   ``resolv.conf`` are controlled via the ``dnsPolicy`` field of a spec. When
   running directly on a host, it will use the host's file.  Irrespective of
   how the DNS lookups are configured, TTLs and caches on the resolver will
   impact the IPs seen by the ``cilium-agent`` lookups.

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
                // ranges in the form "1024-2048
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

        .. literalinclude:: ../../examples/policies/l4/l4.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l4/l4.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l4/l4.json

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

        .. literalinclude:: ../../examples/policies/l4/l3_l4_combined.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l4/l3_l4_combined.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l4/l3_l4_combined.json

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

        .. literalinclude:: ../../examples/policies/l4/cidr_l4_combined.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l4/cidr_l4_combined.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l4/cidr_l4_combined.json



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
          violate the policy.

.. note:: There is currently a max limit of 40 ports with layer 7 policies per
          endpoint. This might change in the future when support for ranges is
          added.

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

        .. literalinclude:: ../../examples/policies/l7/http/simple/l7.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l7/http/simple/l7.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l7/http/simple/l7.json

All GET /path1 and PUT /path2 when header set
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example limits all endpoints which carry the labels
``app=myService`` to only be able to receive packets on port 80 using TCP.
While communicating on this port, the only API endpoints allowed will be ``GET
/path1`` and ``PUT /path2`` with the HTTP header ``X-My_header`` set to
``true``:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l7/http/http.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l7/http/http.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l7/http/http.json


Kafka (Tech Preview)
--------------------

.. note:: Kafka support is currently in tech preview phase. Tech preview is
          functionality that has recently been added and had limited user
          exposure so far.


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

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka-role.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka-role.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka-role.json

Allow producing to topic empire-announce using apiKeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka.json

Kubernetes
==========

This section covers Kubernetes specific network policy aspects.

.. _k8s_namespaces:

Namespaces
----------

`Namespaces <https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/>`_
are used to create virtual clusters within a Kubernetes cluster. All Kubernetes objects
including NetworkPolicy and CiliumNetworkPolicy belong to a particular
namespace. Depending on how a policy is being defined and created, Kubernetes
namespaces are automatically being taken into account:

* Network policies created and imported as `CiliumNetworkPolicy` CRD and
  `NetworkPolicy` apply within the namespace, i.e. the policy only applies
  to pods within that namespace. It is however possible to grant access to and
  from pods in other namespaces as described below.

* Network policies imported directly via the :ref:`api_ref` apply to all
  namespaces unless a namespace selector is specified as described below.

.. note:: While specification of the namespace via the label
	  ``k8s:io.kubernetes.pod.namespace`` in the ``fromEndpoints`` and
	  ``toEndpoints`` fields is deliberately supported. Specification of the
	  namespace in the ``endpointSelector`` is prohibited as it would
	  violate the namespace isolation principle of Kubernetes. The
	  ``endpointSelector`` always applies to pods of the namespace which is
	  associated with the CiliumNetworkPolicy resource itself.

Example: Enforce namespace boundaries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example demonstrates how to enforce Kubernetes namespace-based boundaries
for the namespaces ``ns1`` and ``ns2`` by enabling default-deny on all pods of
either namespace and then allowing communication from all pods within the same
namespace.

.. note:: The example locks down ingress of the pods in ``ns1`` and ``ns2``.
	  This means that the pods can still communicate egress to anywhere
	  unless the destination is in either ``ns1`` or ``ns2`` in which case
	  both source and destination have to be in the same namespace. In
	  order to enforce namespace boundaries at egress, the same example can
	  be used by specifying the rules at egress in addition to ingress.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/kubernetes/namespace/isolate-namespaces.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/kubernetes/namespace/isolate-namespaces.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/kubernetes/namespace/isolate-namespaces.json

Example: Expose pods across namespaces
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example exposes all pods with the label ``name=leia`` in the
namespace ``ns1`` to all pods with the label ``name=luke`` in the namespace
``ns2``.

Refer to the :git-tree:`example YAML files <examples/policies/kubernetes/namespace/demo-pods.yaml>`
for a fully functional example including pods deployed to different namespaces.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/kubernetes/namespace/namespace-policy.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/kubernetes/namespace/namespace-policy.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/kubernetes/namespace/namespace-policy.json

Example: Allow egress to kube-dns in kube-system namespace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example allows all pods in the namespace in which the policy is
created to communicate with kube-dns on port 53/UDP in the ``kube-system``
namespace.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/kubernetes/namespace/kubedns-policy.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/kubernetes/namespace/kubedns-policy.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/kubernetes/namespace/kubedns-policy.json


ServiceAccounts
----------------

Kubernetes `Service Accounts
<https://kubernetes.io/docs/concepts/configuration/assign-pod-node/>`_ are used
to associate an identity to a pod or process managed by Kubernetes and grant
identities access to Kubernetes resources and secrets. Cilium supports the
specification of network security policies based on the service account
identity of a pod.

The service account of a pod is either defined via the `service account
admission controller
<https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#serviceaccount>`_
or can be directly specified in the Pod, Deployment, ReplicationController
resource like this:

.. code:: bash

        apiVersion: v1
        kind: Pod
        metadata:
          name: my-pod
        spec:
          serviceAccountName: leia
          ...

Example
~~~~~~~

The following example grants any pod running under the service account of
"luke" to issue a ``HTTP GET /public`` request on TCP port 80 to all pods
running associated to the service account of "leia".

Refer to the :git-tree:`example YAML files <examples/policies/kubernetes/serviceaccount/demo-pods.yaml>`
for a fully functional example including deployment and service account
resources.


.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/kubernetes/serviceaccount/serviceaccount-policy.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/kubernetes/serviceaccount/serviceaccount-policy.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/kubernetes/serviceaccount/serviceaccount-policy.json

