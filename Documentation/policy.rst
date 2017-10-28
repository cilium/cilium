.. _policy_guide:

##############
Network Policy
##############

This chapter documents the policy language used to configure network policies
in Cilium. Security policies can be specified and imported via the following
mechanisms:

* Using Kubernetes ``NetworkPolicy`` and ``CiliumNetworkPolicy`` resources. See
  the section k8s_policy_ for more details. In this mode, Kubernetes will
  automatically distribute the policies to all agents.

* Directly imported via the :ref:`api_ref` of the agent. This method does
  automatically distribute policies to all agents. It is in the responsibility
  of the API user to import the policy in all required agents.

.. versionadded:: future
   Use of the KVstore to distribute security policies is on the roadmap but has
   not been implemented yet.

***************
Policy Language
***************

All policy rules share a common base type which specifies what endpoints the
rule applies to and also carries common metadata to identify the rule.

Rule
====

Each rule is split into an ingress section which contains the rules which must
be applied at ingress and egress of all endpoints matching the endpoint
selector.  Either ingress, egress, or both can be provided. If both ingress and
egress are omitted, the rule has no effect.

::

        type Rule struct {
                // EndpointSelector selects all endpoints which should be subject to
                // this rule. Cannot be empty.
                EndpointSelector EndpointSelector `json:"endpointSelector"`

                // Ingress is a list of IngressRule which are enforced at ingress.
                // If omitted or empty, this rule does not apply at ingress.
                //
                // +optional
                Ingress []IngressRule `json:"ingress,omitempty"`

                // Egress is a list of EgressRule which are enforced at egress.
                // If omitted or empty, this rule does not apply at egress.
                //
                // +optional
                Egress []EgressRule `json:"egress,omitempty"`

                // Labels is a list of optional strings which can be used to
                // re-identify the rule or to store metadata. It is possible to lookup
                // or delete strings based on labels. Labels are not required to be
                // unique, multiple rules can have overlapping or identical labels.
                //
                // +optional
                Labels labels.LabelArray `json:"labels,omitempty"`

                // Description is a free form string, it can be used by the creator of
                // the rule to store human readable explanation of the purpose of this
                // rule. Rules cannot be identified by comment.
                //
                // +optional
                Description string `json:"description,omitempty"`
        }

----

endpointSelector
  Selects the endpoints to which the policy rules contained must be applied to.
  All endpoints which match the labels specified in the ``endpointSelector``
  will have the policy rules applied to. See the LabelSelector_ section in the
  Kubernetes documentation for the definition of an ``endpointSelector``.

ingress
  List of rules which must apply at ingress of the endpoint, i.e. to all
  network packets which are entering the endpoint.

egress
  List of rules which must apply at egress of the endpoint, i.e. to all network
  packets which are leaving the endpoint.

labels
  Labels are used to identify the rule. Rules can be listed and deleted by
  labels. Policy rules which are imported via :ref:`k8s_policy` automatically
  get the label ``io.cilium.k8s-policy-name=NAME`` assigned where ``NAME``
  corresponds to the name specified in the ``NetworkPolicy`` or
  ``CiliumNetworkPolicy`` resource.

description
  Description is a string which is not interpreted by Cilium. It can be used to
  describe the intent and scope of the rule in a human readable form.

Layer 3: Labels-Based
=====================

The L3 policy specifies which endpoints can talk to each other. L3 policies can
be specified using :ref:`labels` or CIDR. For CIDR, refer to the
:ref:`policy_cidr` section below.

Label-based L3 policy is used to establish policy between endpoints inside the
cluster. An endpoint is allowed to talk to another endpoint if at least one
rule exists which selects the destination endpoint with the
``endpointSelector`` while also selecting the source endpoint in the
``fromEndpoints`` field. Like ``endpointSelector``, the ``fromEndpoints`` is
specified as a LabelSelector_.

For more complex label combinations, the ``fromRequires`` field can be used to
establish label requirements which apply to multiple destinations.
``fromRequires`` is a list of additional constraints which must be met in order
for the selected endpoints to be reachable. These additional constraints do no
by itself grant access privileges and must always be accompanied with at least
one matching fromEndpoints.

::

        type IngressRule struct {
                // FromEndpoints is a list of endpoints identified by an
                // EndpointSelector which are allowed to communicate with the endpoint
                // subject to the rule.
                //
                // Example:
                // Any endpoint with the label "role=backend" can be consumed by any
                // endpoint carrying the label "role=frontend".
                //
                // +optional
                FromEndpoints []EndpointSelector `json:"fromEndpoints,omitempty"`

                // FromRequires is a list of additional constraints which must be met
                // in order for the selected endpoints to be reachable. These
                // additional constraints do no by itself grant access privileges and
                // must always be accompanied with at least one matching FromEndpoints.
                //
                // Example:
                // Any Endpoint with the label "team=A" requires consuming endpoint
                // to also carry the label "team=A".
                //
                // +optional
                FromRequires []EndpointSelector `json:"fromRequires,omitempty"`

                // [...]
        }

Example (Basic)
---------------

This example shows to enable all endpoints with the label ``role=frontend`` to
communicate with all endpoints with the label ``role=backend``:

.. literalinclude:: ../examples/policies/l3.json

Example (Requires)
------------------

The following example builds on top of the previous one but requires that *all*
endpoints which carry the label ``env=prod`` require the consumer to also carry
the label ``env=prod`` in order for access to be granted:

.. literalinclude:: ../examples/policies/requires.json

.. _policy_cidr:

Layer 3: Entities
~~~~~~~~~~~~~~~~~

There is an additional syntactic sugar for explicitly whitelisting ``world`` and ``host`` entities:

.. literalinclude:: ../examples/policies/entities.json

Layer 3: IP/CIDR based
======================

CIDR policies are used to define policies to and from endpoints which are not
managed by a container orchestration system and thus do not have labels
associated with them. These are typically VMs or bare metal machines with
static IP addresses. CIDR policy can also be used to limit access to external
services, for example to limit external access to a particular IP range.

CIDR policies can be applied at ingress and egress:

::

        type IngressRule struct {
                // FromCIDR is a list of IP blocks which the endpoint subject to the
                // rule is allowed to receive connections from in addition to FromEndpoints.
                // This will match on the source IP address of incoming connections. Adding
                // a prefix into FromCIDR or into FromCIDRSet with no ExcludeCIDRs is
                // equivalent. Overlaps are allowed between FromCIDR and FromCIDRSet.
                //
                // Example:
                // Any endpoint with the label "app=my-legacy-pet" is allowed to receive
                // connections from 10.3.9.1
                //
                // +optional
                FromCIDR []CIDR `json:"fromCIDR,omitempty"`
                
                // FromCIDRSet is a list of IP blocks which the endpoint subject to the
                // rule is allowed to receive connections from in addition to FromEndpoints,
                // along with a list of subnets contained within their corresponding IP block
                // from which traffic should not be allowed.
                // This will match on the source IP address of incoming connections. Adding
                // a prefix into FromCIDR or into FromCIDRSet with no ExcludeCIDRs is
                // equivalent. Overlaps are allowed between FromCIDR and FromCIDRSet.
                //
                // Example:
                // Any endpoint with the label "app=my-legacy-pet" is allowed to receive
                // connections from 10.0.0.0/8 except from IPs in subnet 10.96.0.0/12.
                //
                // +optional
                FromCIDRSet []CIDRRule `json:"fromCIDRSet,omitempty"
                // [...]
        }

        type EgressRule struct {
                // ToCIDR is a list of IP blocks which the endpoint subject to the rule
                // is allowed to initiate connections to in addition to connections
                // which are allowed via FromEndpoints. This will match on the
                // destination IP address of outgoing connections. Adding a prefix into
                // ToCIDR or into ToCIDRSet with no ExcludeCIDRs is equivalent. Overlaps
                // are allowed between ToCIDR and ToCIDRSet.
                //
                // Example:
                // Any endpoint with the label "app=database-proxy" is allowed to
                // initiate connections to 10.2.3.0/24
                //
                // +optional
                ToCIDR []CIDR `json:"toCIDR,omitempty"`
                
                // ToCIDRSet is a list of IP blocks which the endpoint subject to the rule
                // is allowed to initiate connections to in addition to connections
                // which are allowed via FromEndpoints, along with a list of subnets contained
                // within their corresponding IP block to which traffic should not be
                // allowed. This will match on the destination IP address of outgoing
                // connections. Adding a prefix into ToCIDR or into ToCIDRSet with no
                // ExcludeCIDRs is equivalent. Overlaps are allowed between ToCIDR and
                // ToCIDRSet.
                //
                // Example:
                // Any endpoint with the label "app=database-proxy" is allowed to
                // initiate connections to 10.2.3.0/24 except from IPs in subnet 10.2.3.0/28.
                //
                // +optional
                ToCIDRSet []CIDRRule `json:"toCIDRSet,omitempty"`
                // [...]
        }


fromCIDR
  List of source prefixes/CIDRs that are allowed to talk to all endpoints
  selected by the ``endpointSelector``. Note that this list is **in addition**
  to the ``fromEndpoints`` specified. It is not required to allow the IPs of
  endpoints if the endpoints are already allowed to communicate based on
  ``fromEndpoints`` rules.

fromCIDRSet
  List of source prefixes/CIDRs that are allowed to talk to all endpoints
  selected by the ``endpointSelector``, along with an optional list of
  prefixes/CIDRs per source prefix/CIDR that are subnets of the source
  prefix/CIDR from which communication is not allowed. Like ``fromCIDR``
  it is not required to list the IPs of endpoints if the endpoints are
  already allowed to communicate based on ``fromEndpoints`` rules.

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

Example
-------

This example shows how to allow all endpoints with the label ``app=myService``
to talk to the external IP ``20.1.1.1``, as well as the CIDR prefix ``10.0.0.0/8``,
but not CIDR prefix ``10.96.0.0/12``

.. literalinclude:: ../examples/policies/cidr.json

Layer 3: Services
~~~~~~~~~~~~~~~~~

Services running in your cluster can be whitelisted in Egress rules. Currently only headless
Kubernetes services defined by their name and namespace are supported. More documentation on HeadlessServices_.
Future versions of Cilium will support specifying non Kubernetes services and services which are backed by pods.

::

        type EgressRule struct {
                // [...]
                // ToServices is a list of services to which the endpoint subject
                // to the rule is allowed to initiate connections.
                ToServices []Service `json:"toServices,omitempty"`
                // [...]
        }

        type Service struct {
            // [...]
            // K8sService selects service by name and namespace pair
            K8sService K8sServiceNamespace `json:"k8sService,omitempty"`
        }

        type K8sServiceNamespace struct {
            ServiceName string `json:"serviceName,omitempty"`
            Namespace   string `json:"namespace,omitempty"`
        }


Example
-------

This example shows how to allow all endpoints with the label ``id=app2``
to talk to all endpoints of kubernetes service ``myservice`` in kubernetes
namespace ``default``. Note that ``myservice`` needs to be a headless service
for this policy to take effect.

.. literalinclude:: ../examples/policies/service.json

.. _policy_l4:

Layer 4: Ports
==============

L4 policy can be specified in addition to L3 policies. It restricts the ability
of an endpoint to emit and/or receive packets on a particular port using a
particular protocol. If no L4 policy is specified for an endpoint, that
endpoint is allowed to send and receive on all L4 ports and protocols.

L4 policy can be specified at both ingress and egress using the `toPorts`
field::

        type IngressRule struct {
                // ToPorts is a list of destination ports identified by port number and
                // protocol which the endpoint subject to the rule is allowed to
                // receive connections on.
                //
                // Example:
                // Any endpoint with the label "app=httpd" can only accept incoming
                // connections on port 80/tcp.
                //
                // +optional
                ToPorts []PortRule `json:"toPorts,omitempty"`

                // [...]
        }

        type EgressRule struct {
                // ToPorts is a list of destination ports identified by port number and
                // protocol which the endpoint subject to the rule is allowed to
                // connect to.
                //
                // Example:
                // Any endpoint with the label "role=frontend" is allowed to initiate
                // connections to destination port 8080/tcp
                //
                // +optional
                ToPorts []PortRule `json:"toPorts,omitempty"`

                // [...]
        }

The ``toPorts`` field takes a ``PortProtocol`` structure which is defined as follows::

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

.. note:: There is currently a max limit of 40 ports. This might change in the
          future when support for ranges is added.

Example (L4)
------------

The following rule limits all endpoints with the label ``app=myService`` to
only be able to emit packets using TCP on port 80:

.. literalinclude:: ../examples/policies/l4.json

Example (Combining Labels + L4)
-------------------------------

This example enables all endpoints with the label ``role=frontend`` to
communicate with all endpoints with the label ``role=backend``, but they must
communicate using using TCP on port 80:

.. literalinclude:: ../examples/policies/l3_l4_combined.json

Example (Multiple Rules with Labels, L4)
----------------------------------------

This example is similar to the previous, but rather than restricting
communication to only endpoints communicating over TCP on port 80 from
``role=frontend``, it allows all traffic from endpoints with the label
``role=frontend`` to reach ``role=backend``, *as well as* traffic from any
endpoint that is communicating over TCP on port 80:

.. literalinclude:: ../examples/policies/multi_rule.json

Layer 7 - HTTP
==============

Layer 7 policy can be specified embedded into policy_l4_ rules. The ``L7Rules``
structure is a base type containing an enumeration of protocol specific fields
which will be extended as Cilium starts supporting additional layer 7
protocols. Only one field can be specified at the time.

Layer 7 policies can be specified for ingress and egress policy_l4_ rules::

        // L7Rules is a union of port level rule types. Mixing of different port
        // level rule types is disallowed, so exactly one of the following must be set.
        // If none are specified, then no additional port level rules are applied.
        type L7Rules struct {
                // HTTP specific rules.
                //
                // +optional
                HTTP []PortRuleHTTP `json:"http,omitempty"`
        }

HTTP
  If specified, will restrict all HTTP requests which are sent or received on
  the ``PortProtocol`` to which the ``L7Rules`` to the list of specified
  request patterns.

HTTP Policy
-----------

Unlike L3 and L4 policies, violation of Layer 7 rules does not result in packet
drops. Instead, if possible, an access denied message such as an *HTTP 403
access denied* is sent back to the sending endpoint.

::

        // PortRuleHTTP is a list of HTTP protocol constraints. All fields are
        // optional, if all fields are empty or missing, the rule does not have any
        // effect.
        //
        // All fields of this type are extended POSIX regex as defined by IEEE Std
        // 1003.1, (i.e this follows the egrep/unix syntax, not the perl syntax)
        // matched against the path of an incoming request. Currently it can contain
        // characters disallowed from the conventional "path" part of a URL as defined
        // by RFC 3986.
        type PortRuleHTTP struct {
                // Path is an extended POSIX regex matched against the path of a
                // request. Currently it can contain characters disallowed from the
                // conventional "path" part of a URL as defined by RFC 3986. Paths must
                // begin with a '/'.
                //
                // If omitted or empty, all paths are all allowed.
                //
                // +optional
                Path string `json:"path,omitempty" protobuf:"bytes,1,opt,name=path"`

                // Method is an extended POSIX regex matched against the method of a
                // request, e.g. "GET", "POST", "PUT", "PATCH", "DELETE", ...
                //
                // If omitted or empty, all methods are allowed.
                //
                // +optional
                Method string `json:"method,omitempty" protobuf:"bytes,1,opt,name=method"`

                // Host is an extended POSIX regex matched against the host header of a
                // request, e.g. "foo.com"
                //
                // If omitted or empty, the value of the host header is ignored.
                //
                // +optional
                Host string `json:"host,omitempty" protobuf:"bytes,1,opt,name=method"`

                // Headers is a list of HTTP headers which must be present in the
                // request. If omitted or empty, requests are allowed regardless of
                // headers present.
                //
                // +optional
                Headers []string `json:"headers,omitempty"`
        }

Path
  When specified, the path field of the request must match the regular
  expression specified.

Method
  When specified, the method name of the request must match the regular
  expression specified.

Host
  When specified, the host field of the request must match the regular
  expression specified.

Headers
  When specified, the request must contain all the headers specified in the
  list.

Example (HTTP)
~~~~~~~~~~~~~~

The following example limits all endpoints which carry the labels
``app=myService`` to only be able to receive packets on port 80 using TCP.
While communicating on this port, the only API endpoints allowed will be ``GET
/path1`` and ``PUT /path2`` with the HTTP header ``X-My_header`` set to
``true``:

.. literalinclude:: ../examples/policies/http.json

.. _policy_tracing:

************
Integrations
************

.. _k8s_policy:

Kubernetes
==========

If you are running Cilium on Kubernetes, you can benefit from the native
support of network security policies. In this mode, Kubernetes is responsible
for distributing the policies across all nodes and Cilium will automatically
apply the policies. Two formats are available to configure network policies
natively with Kubernetes:

- The standard NetworkPolicy_ resource which at the time of this writing,
  supports to specify L3/L4 ingress policies. See the official Kubernetes
  documentation on NetworkPolicy_ for details on how to specify such policies.

- The extended ``CiliumNetworkPolicy`` format which is available as a
  ThirdPartyResource_ and CustomResourceDefinition_ which supports to
  specify L3/L4/L7 policies at both ingress and egress.


JSON specification for ``CiliumNetworkPolicy``:

::

        // CiliumNetworkPolicy is a Kubernetes third-party resource with an
        // extended version of NetworkPolicy
        type CiliumNetworkPolicy struct {
                metav1.TypeMeta `json:",inline"`
                // +optional
                Metadata metav1.ObjectMeta `json:"metadata"`

                // Spec is the desired Cilium specific rule specification.
                Spec *api.Rule `json:"spec,omitempty"`

                // Specs is a list of desired Cilium specific rule specification.
                Specs api.Rules `json:"specs,omitempty"`
        }

A ``CiliumNetworkPolicy`` can contain either a single rule (``Spec``) or a list
of rules (``Specs``). If a list of rules are specified, all rules will be added
and removed atomically.  This is useful if multiple rules depend on each other
and may not be applied independently.

The ``Spec`` respectively ``Specs`` field refers to a standard Cilium Policy
Rule.

Example (Single Rule)
---------------------

The following example allows all prod-labeled pods to access ``/public`` HTTP
endpoint on service-labeled.

.. code:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    description: "L7 policy for accessing /public address on service endpoints"
    metadata:
      name: "rule1"
    spec:
      endpointSelector:
        matchLabels:
          app: service
      ingress:
      - fromEndpoints:
        - matchLabels:
            env: prod
        toPorts:
        - ports:
          - port: "80"
            protocol: TCP
          rules:
            http:
            - method: "GET"
              path: "/public"

Example (Multiple Rules)
------------------------

This example builds on previous example to show how to define multiple policy specs
in single rule. Added spec allows production pods to POST requests to ``external-service.org``.

.. code:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: "fancyrule"
    specs:
      - endpointSelector:
          matchLabels:
            app: service
        ingress:
        - fromEndpoints:
          - matchLabels:
              env: prod
          toPorts:
          - ports:
            - port: "80"
              protocol: TCP
            rules:
              http:
              - method: "GET"
                path: "/public"
      - endpointSelector:
          matchLabels:
            env: prod
        egress:
        - toPorts:
          - ports:
            - port: "80"
              protocol: TCP
            rules:
              http:
              - method: "POST"
                host: "^external-service.org$"

***********************
Policy Enforcement Mode
***********************

Whether an endpoint accepts traffic from any source is dependent upon the
configuration for policy enforcement in the daemon. 

Policy enforcement is configurable at runtime by running:

.. code:: bash

    cilium config PolicyEnforcement={default,always,never}

If you want to have a certain policy enforcement configuration value at
launch-time , you can provide the following flag when you launch the Cilium
daemon:

.. code:: bash

    enable-policy={default,always,never}

Cilium has three different modes for policy enforcement:

* **default**

This is the behavior for policy enforcement when Cilium is launched without
any specified value for policy enforcement configuration. It is based off of
Kubernetes_ behavior for allowing traffic from outside sources. Specifically,
by default, endpoints receive traffic from any source (policy enforcement is
disabled for endpoints). When a policy rule is added to Cilium that selects an
endpoint, the endpoint will not allow traffic except that which is specified
by the rule (policy enforcement is enabled).

* **always**

With this mode, policy enforcement is enabled on all endpoints, even if no
rules select specific endpoints.
 
* **never**

With this mode, policy enforcement is disabled on all endpoints, even if rules
do select specific endpoints. In other words, all traffic is allowed from any
source with respect to an endpoint.

*******
Tracing
*******

If Cilium is denying connections which it shouldn't. There is an easy way to
verify if and why Cilium is denying connectivity in between particular
endpoints. The following example shows how to use ``cilium policy trace`` to
simulate a policy decision from an endpoint with the label ``id.curl`` to an
endpoint with the label ``id.http`` on port 80:

.. code:: bash

    $ cilium policy trace -s id.curl -d id.httpd --dport 80
    Tracing From: [container:id.curl] => To: [container:id.httpd] Ports: [80/any]
    * Rule {"matchLabels":{"any:id.httpd":""}}: selected
        Allows from labels {"matchLabels":{"any:id.curl":""}}
          Found all required labels
            Rule restricts traffic to specific L4 destinations; deferring policy decision to L4 policy stage
    1/1 rules selected
    Found no allow rule
    Label verdict: undecided

    Resolving egress port policy for [container:id.curl]
    * Rule {"matchLabels":{"any:id.curl":""}}: selected
      Allows Egress port [{80 tcp}]
        Found all required labels
    1/1 rules selected
    Found allow rule
    L4 egress verdict: allowed

    Resolving ingress port policy for [container:id.httpd]
    * Rule {"matchLabels":{"any:id.httpd":""}}: selected
      Allows Ingress port [{80 tcp}]
        Found all required labels
    1/1 rules selected
    Found allow rule
    L4 ingress verdict: allowed

    Final verdict: ALLOWED

.. _NetworkPolicy: https://kubernetes.io/docs/concepts/services-networking/network-policies/

.. _ThirdPartyResource: https://kubernetes.io/docs/tasks/access-kubernetes-api/extend-api-third-party-resource/
.. _CustomResourceDefinition: https://kubernetes.io/docs/concepts/api-extension/custom-resources/#customresourcedefinitions
.. _LabelSelector: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
.. _Kubernetes: https://kubernetes.io/docs/concepts/services-networking/network-policies/#isolated-and-non-isolated-pods
.. _HeadlessServices: https://kubernetes.io/docs/concepts/services-networking/service/#headless-services
