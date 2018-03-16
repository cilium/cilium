.. _policy_examples:

Layer 3 Examples
================

The layer 3 policy establishes the base connectivity rules regarding which endpoints
can talk to each other. Layer 3 policies can be specified using two methods:

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
   the cluster. Future versions will allow to define your own entities.

* `CIDR based`: This is used to describe the relationship to or from external
  services if the remote peer is not an endpoint. This requires to hardcode either
  IP addresses or subnets into the policies. This construct should be used as a
  last resort as it requires stable IP or subnet assignments.

.. _Labels based:

Labels Based
------------

Label-based L3 policy is used to establish policy between endpoints inside the
cluster managed by Cilium. An endpoint is allowed to talk to another endpoint
if at least one rule exists which selects the destination endpoint with the
`EndpointSelector` in the ``endpointSelector`` field and selects the source
endpoint with the `EndpointSelector` in the ``fromEndpoints`` field.

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
all ingress traffic to an endpoint is simple:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/ingress-allow-all/ingress-allow-all.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/ingress-allow-all/ingress-allow-all.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/ingress-allow-all/ingress-allow-all.json

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
there must also be rules which match ``fromEndpoints``.

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

Services running in your cluster can be whitelisted in Egress rules. Currently
headless Kubernetes services defined by their name and namespace or label selector
are supported. More documentation on `HeadlessServices`.
Future versions of Cilium will support specifying non Kubernetes services and services
which are backed by pods.

This example shows how to allow all endpoints with the label ``id=app2``
to talk to all endpoints of kubernetes service ``myservice`` in kubernetes
namespace ``default``. Note that ``myservice`` needs to be a headless service
for this policy to take effect.

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
  The local host serving the endpoint

world
  The world outside of the cluster.

all
  Everyone

Access to/from local host
~~~~~~~~~~~~~~~~~~~~~~~~~

Allow all endpoints with the label ``env=dev`` to access the host that is
serving the particular endpoint.

.. note:: Kubernetes will automatically allow all communication from and to the
	  local host of all local endpoints. You can run the agent with the
	  option ``--allow-localhost=policy`` to disable this behaviour which
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
example to limit external access to a particular IP range.

CIDR policies can be applied at ingress or egress. On Ingress:

fromCIDR
  List of source prefixes/CIDRs that are allowed to talk to all endpoints
  selected by the ``endpointSelector``. It is not required to allow the IPs of
  endpoints if the endpoints are already allowed to communicate based on
  ``fromEndpoints`` rules.

fromCIDRSet
  List of source prefixes/CIDRs that are allowed to talk to all endpoints
  selected by the ``endpointSelector``, along with an optional list of
  prefixes/CIDRs per source prefix/CIDR that are subnets of the source
  prefix/CIDR from which communication is not allowed. Like ``fromCIDR``
  it is not required to list the IPs of endpoints if the endpoints are
  already allowed to communicate based on ``fromEndpoints`` rules.

On Egress:

toCIDR:
  List of destination prefixes/CIDRs that endpoints selected by
  ``endpointSelector`` are allowed to talk to. Note that endpoints which are
  selected by a ``fromEndpoints`` are automatically allowed to talk to their
  respective destination endpoints. It is not required to list the IP of
  destination endpoints.

toCIDRSet
  List of destination prefixes/CIDRs that are allowed to talk to all endpoints
  selected by the ``endpointSelector``, along with an optional list of
  prefixes/CIDRs per source prefix/CIDR that are subnets of the destination
  prefix/CIDR to which communication is not allowed. Like toCIDR, it is not
  required to list the IPs of destination endpoints if they are already
  selected by a ``fromEndpoints``.

Restrict to external CIDR block
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

.. _l4_policy:

Layer 4 Examples
================

Limit ingress/egress ports
--------------------------

Layer 4 policy can be specified in addition to layer 3 policies or independently.
It restricts the ability of an endpoint to emit and/or receive packets on a
particular port using a particular protocol. If no layer 4 policy is specified
for an endpoint, the endpoint is allowed to send and receive on all layer 4
ports and protocols. Layer 4 policies apply to ports after service port mapping
has been applied.

Layer 4 policy can be specified at both ingress and egress using the
``toPorts`` field:

The ``toPorts`` field takes a ``PortProtocol`` structure which is defined as follows:

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

.. note:: There is currently a max limit of 40 ports per endpoint. This might
          change in the future when support for ranges is added.

Example (L4)
~~~~~~~~~~~~

The following rule limits all endpoints with the label ``app=myService`` to
only be able to emit packets using TCP on port 80:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l4/l4.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l4/l4.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l4/l4.json

Labels dependent Layer 4 rule
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example enables all endpoints with the label ``role=frontend`` to
communicate with all endpoints with the label ``role=backend``, but they must
communicate using using TCP on port 80:

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l4/l3_l4_combined.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l4/l3_l4_combined.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l4/l3_l4_combined.json

Layer 7 Examples
================

Layer 7 policy rules are embedded into `l4_policy` rules and can be specified
for ingress and egress. ``L7Rules`` structure is a base type containing an
enumeration of protocol specific fields.

The structure is implemented as a union, i.e. only one member field can be used
per port. If multiple ``toPorts`` rules with identical ``PortProtocol`` select
an overlapping list of endpoints, then the Layer 7 rules are combined together
if they are of the same type. If the type differs, the policy is rejected.

Each member consists of a list of application protocol rules. An Layer 7
request is permitted if at least one of the rules matches. If no rules are
specified, then all traffic is permitted.


.. note:: Layer 7 rules can currently not be made dependent on layer 3 and 4
          rules. This feature is currently being added to the respective
          datapath components.

::

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

.. note:: Unlike Layer 3 and Layer 4 policies, violation of Layer 7 rules does
          not result in packet drops. Instead, if possible, an application
          protocol specific access denied message is crafted and returned, e.g.
          an *HTTP 403 access denied* is sent back for HTTP requests which
          violate the policy.

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

The following fields can be matched on:

Role
  Role is a case-insensitive string and describes a group of API keys
  necessary to perform certain higher level Kafka operations such as "produce"
  or "consume". A Role automatically expands into all APIKeys required
  to perform the specified higher level operation.

  The following values are supported:
	- "produce": Allow producing to the topics specified in the rule
	- "consume": Allow consuming from the topics specified in the rule
  This field is incompatible with the APIKey field, either APIKey or Role
  may be specified. If omitted or empty, all keys are allowed, if APIKey is also
  the empty

APIKey
  APIKey is a case-insensitive string matched against the key of a request,
  e.g. "produce", "fetch", "createtopic", "deletetopic", et al Reference:
  https://kafka.apache.org/protocol#protocol_api_keys.  If omitted or empty,
  all keys are allowed.

APIVersion
  APIVersion is the version matched against the api version of the Kafka
  message. If set, it has to be a string representing a positive integer. If
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
  multiple topics, then all topics must be allowed or the message will be
  rejected.

  This constraint is ignored if the matched request message type doesn't
  contain any topic. Maximum size of Topic can be 249 characters as per recent
  Kafka spec and allowed characters are a-z, A-Z, 0-9, -, . and _ Older Kafka
  versions had longer topic lengths of 255, but in Kafka 0.10 version the
  length was changed from 255 to 249. For compatibility reasons we are using
  255

  If omitted or empty, all topics are allowed.

Only allow producing to topic empire-announce using Role
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka-Role.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka-Role.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka-Role.json

Only allow producing to topic empire-announce using apiKeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l7/kafka/kafka.json

