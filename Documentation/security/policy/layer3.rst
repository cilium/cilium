.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _l3_policy:

Layer 3 Policies
================

The layer 3 policy establishes the base connectivity rules regarding which endpoints
can talk to each other. Layer 3 policies can be specified using the following methods:

* `Endpoints based`: This is used to describe the relationship if both
  endpoints are managed by Cilium and are thus assigned labels. The
  advantage of this method is that IP addresses are not encoded into the
  policies and the policy is completely decoupled from the addressing.

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

* `Node based`: This is an extension of ``remote-node`` entity. Optionally nodes
  can have unique identity that can be used to allow/block access only from specific ones.

* `CIDR based`: This is used to describe the relationship to or from external
  services if the remote peer is not an endpoint. This requires to hardcode either
  IP addresses or subnets into the policies. This construct should be used as a
  last resort as it requires stable IP or subnet assignments.

* `DNS based`: Selects remote, non-cluster, peers using DNS names converted to
  IPs via DNS lookups. It shares all limitations of the `CIDR based` rules
  above. DNS information is acquired by routing DNS traffic via `DNS Proxy`
  with a separate policy rule.
  DNS TTLs are respected.

.. _Endpoints based:

Endpoints based
---------------

Endpoints-based L3 policy is used to establish rules between endpoints inside
the cluster managed by Cilium. Endpoints-based L3 policies are defined by using
an `EndpointSelector` inside a rule to select what kind of traffic can be
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

.. literalinclude:: ../../../examples/policies/l3/simple/l3.yaml
  :language: yaml


Ingress Allow All Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~

An empty `EndpointSelector` will select all endpoints, thus writing a rule that will allow
all ingress traffic to an endpoint may be done as follows:

.. literalinclude:: ../../../examples/policies/l3/ingress-allow-all/ingress-allow-all.yaml
  :language: yaml

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

.. literalinclude:: ../../../examples/policies/l3/simple/l3_egress.yaml
  :language: yaml

Egress Allow All Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~

An empty `EndpointSelector` will select all egress endpoints from an endpoint
based on the `CiliumNetworkPolicy` namespace (``default`` by default). The
following rule allows all egress traffic from endpoints with the label
``role=frontend`` to all other endpoints in the same namespace:

.. literalinclude:: ../../../examples/policies/l3/egress-allow-all/egress-allow-all.yaml
  :language: yaml

Note that while the above examples allow all egress traffic from an endpoint, the receivers
of the egress traffic may have ingress rules that deny the traffic. In other words,
policy must be configured on both sides (sender and receiver).

Simple Egress Deny
~~~~~~~~~~~~~~~~~~

The following example illustrates how to deny communication to endpoints with
the label ``role=backend`` from endpoints with the label ``role=frontend``.
If an ``egressDeny`` rule matches, egress traffic is denied even if the policy
contains ``egress`` rules that would otherwise allow it.

.. literalinclude:: ../../../examples/policies/l3/egress-deny/egress-deny.yaml
   :language: yaml

Ingress/Egress Default Deny
~~~~~~~~~~~~~~~~~~~~~~~~~~~

An endpoint can be put into the default deny mode at ingress or egress if a
rule selects the endpoint and contains the respective rule section ingress or
egress.

.. note:: Any rule selecting the endpoint will have this effect, this example
          illustrates how to put an endpoint into default deny mode without
          whitelisting other peers at the same time.

.. literalinclude:: ../../../examples/policies/l3/egress-default-deny/egress-default-deny.yaml
  :language: yaml

Additional Label Requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   The ``fromRequires`` and ``toRequires`` fields are deprecated as of Cilium
   1.17.x. They have been removed as of Cilium 1.19.

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

.. warning::

   ``toRequires`` and ``fromRequires`` apply to all rules that share the same
   endpoint selector and are not limited by other egress or ingress rules.
   As a result ``toRequires`` and ``fromRequires`` limits all ingress and egress traffic
   that applies to its endpoint selector. An important implication of the fact
   that ``toRequires`` and ``fromRequires`` limit all ingress and egress traffic
   that applies to an endpoint selector is that the other egress and ingress rules
   (such as ``fromEndpoints``, ``fromPorts``, ``toEntities``, ``toServices``, and the rest)
   do not limit the scope of the ``toRequires`` of ``fromRequires`` fields. Pairing other
   ingress and egress rules with a ``toRequires`` or ``fromRequires`` will result in valid
   policy, but the requirements set in ``toRequires`` and ``fromRequires`` stay in effect
   no matter what would otherwise be allowed by the other rules.


This example shows how to require every endpoint with the label ``env=prod`` to
be only accessible if the source endpoint also has the label ``env=prod``.

.. literalinclude:: ../../../examples/policies/l3/requires/requires.yaml
  :language: yaml

This ``fromRequires`` rule doesn't allow anything on its own and needs to be
combined with other rules to allow traffic. For example, when combined with the
example policy below, the endpoint with label ``env=prod`` will become
accessible from endpoints that have both labels ``env=prod`` and
``role=frontend``.

.. literalinclude:: ../../../examples/policies/l3/requires/endpoints.yaml
  :language: yaml

.. _Services based:

Services based
--------------

Traffic from endpoints to services running in your cluster can be allowed via
``toServices`` statements in Egress rules. Policies can reference
`Kubernetes Services <https://kubernetes.io/docs/concepts/services-networking/service>`_
by name or label selector.

This feature uses the discovered services' `label selector <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors>`_
as an :ref:`endpoint selector <endpoints based>` within the policy.

.. note::

   `Services without selectors <https://kubernetes.io/docs/concepts/services-networking/service/#services-without-selectors>`_
   are handled differently. The IPs in the service's EndpointSlices are, converted to
   :ref:`CIDR <cidr based>` selectors. CIDR selectors cannot select pods,
   and that limitation applies here as well.

   The special Kubernetes Service ``default/kubernetes`` does not use a label
   selector. It is **not recommended** to grant access to the Kubernetes API server
   with a ``toServices``-based policy. Use instead the
   `kube-apiserver entity <kube_apiserver_entity>`.


This example shows how to allow all endpoints with the label ``id=app2``
to talk to all endpoints of Kubernetes Service ``myservice`` in kubernetes
namespace ``default`` as well as all services with label ``env=staging`` in
namespace ``another-namespace``.

.. literalinclude:: ../../../examples/policies/l3/service/service.yaml
  :language: yaml

.. _Entities based:

Entities based
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
    nodes.
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
    remote-node, and init identities. This also includes all remote nodes
    in a clustermesh scenario.
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

.. note:: The ``kube-apiserver`` entity may not work for *ingress traffic* in some Kubernetes
   distributions, such as Azure AKS and GCP GKE. This is due to the fact that ingress
   control-plane traffic is being tunneled through worker nodes, which does not preserve
   the original source IP. You may be able to use a broader ``fromEntities: cluster`` rule
   instead. Restricting *egress traffic* via ``toEntities: kube-apiserver`` however is expected
   to work on these Kubernetes distributions.

.. _kube_apiserver_entity:

Access to/from kube-apiserver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Allow all endpoints with the label ``env=dev`` to access the kube-apiserver.

.. literalinclude:: ../../../examples/policies/l3/entities/apiserver.yaml
  :language: yaml

Access to/from local host
~~~~~~~~~~~~~~~~~~~~~~~~~

Allow all endpoints with the label ``env=dev`` to access the host that is
serving the particular endpoint.

.. note:: Kubernetes will automatically allow all communication from the
	  local host of all local endpoints. You can run the agent with the
	  option ``--allow-localhost=policy`` to disable this behavior which
	  will give you control over this via policy.

.. literalinclude:: ../../../examples/policies/l3/entities/host.yaml
  :language: yaml

.. _policy-remote-node:

Access to/from all nodes in the cluster (or clustermesh)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Allow all endpoints with the label ``env=dev`` to receive traffic from any host
in the cluster that Cilium is running on.

.. literalinclude:: ../../../examples/policies/l3/entities/nodes.yaml
  :language: yaml

Access to/from outside cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example shows how to enable access from outside of the cluster to all
endpoints that have the label ``role=public``.

.. literalinclude:: ../../../examples/policies/l3/entities/world.yaml
  :language: yaml

.. _policy_node_based:
.. _Node based:

Node based
----------

.. note:: Example below with ``fromNodes/toNodes`` fields will only take effect when
     ``enable-node-selector-labels`` flag is set to true (or equivalent Helm value
     ``nodeSelectorLabels: true``).

When ``--enable-node-selector-labels=true`` is specified, every cilium-agent
allocates a different local :ref:`security identity <arch_id_security>` for all
other nodes. But instead of using :ref:`local scoped identity <local_scoped_identity>`
it uses :ref:`remote-node scoped identity<remote_node_scoped_identity>` identity range.

By default all labels that ``Node`` object has attached are taken into account,
which might result in allocation of **unique** identity for each remote-node.
For these cases it is also possible to filter only
:ref:`security relevant labels <security relevant labels>` with ``--node-labels`` flag.

This example shows how to allow all endpoints with the label ``env=prod`` to receive
traffic **only** from control plane (labeled
``node-role.kubernetes.io/control-plane=""``) nodes in the cluster (or clustermesh).

Note that by default policies automatically select nodes from all the clusters in
a Cluster Mesh environment unless it is explicitly specified. To restrict node
selection to the local cluster by default you can enable the option
``--policy-default-local-cluster`` via the ConfigMap option ``policy-default-local-cluster``
or the Helm value ``clustermesh.policyDefaultLocalCluster``.

.. literalinclude:: ../../../examples/policies/l3/entities/customnodes.yaml
  :language: yaml

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
* (:ref:`optional <cidr_select_nodes>`) Node IPs within the cluster

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

  ``fromCIDRSet`` may also reference prefixes/CIDRs indirectly via a :ref:`CiliumCIDRGroup`.

Egress
~~~~~~

toCIDR
  List of destination prefixes/CIDRs that endpoints selected by
  ``endpointSelector`` are allowed to talk to. Note that endpoints which are
  selected by a ``fromEndpoints`` are automatically allowed to reply back to
  the respective destination endpoints.

toCIDRSet
  List of destination prefixes/CIDRs that endpoints selected by
  ``endpointSelector`` are allowed to talk to, along with an optional list of
  prefixes/CIDRs per source prefix/CIDR that are subnets of the destination
  prefix/CIDR to which communication is not allowed.

  ``toCIDRSet`` may also reference prefixes/CIDRs indirectly via a :ref:`CiliumCIDRGroup`.

Allow to external CIDR block
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example shows how to allow all endpoints with the label ``app=myService``
to talk to the external IP ``20.1.1.1``, as well as the CIDR prefix ``10.0.0.0/8``,
but not CIDR prefix ``10.96.0.0/12``

.. literalinclude:: ../../../examples/policies/l3/cidr/cidr.yaml
  :language: yaml

.. _cidr_select_nodes:

Selecting nodes with CIDR / ipBlock
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../../beta.rst

By default, CIDR-based selectors do not match in-cluster entities (pods or nodes).
Optionally, you can direct the policy engine to select nodes by CIDR / ipBlock.
This requires you to configure Cilium with ``--policy-cidr-match-mode=nodes`` or
the equivalent Helm value ``policyCIDRMatchMode: nodes``. It is safe to toggle this
option on a running cluster, and toggling the option affects neither upgrades nor downgrades.

When ``--policy-cidr-match-mode=nodes`` is specified, every agent allocates a
distinct local :ref:`security identity <arch_id_security>` for all other nodes.
This slightly increases memory usage -- approximately 1MB for every 1000 nodes
in the cluster.

This is particularly relevant to self-hosted clusters -- that is, clusters where
the apiserver is hosted on in-cluster nodes. Because CIDR-based selectors ignore
nodes by default, you must ordinarily use the ``kube-apiserver`` :ref:`entity <Entities based>`
as part of a CiliumNetworkPolicy. Setting ``--policy-cidr-match-mode=nodes`` permits
selecting the apiserver via an ``ipBlock`` peer in a KubernetesNetworkPolicy.

.. _DNS based:

DNS based
---------

DNS policies are used to define Layer 3 policies to endpoints that are not
managed by Cilium, but have DNS queryable domain names. The IP addresses
provided in DNS responses are allowed by Cilium in a similar manner to IPs in
`CIDR based`_ policies. They are an alternative when the remote IPs may change
or are not know prior, or when DNS is more convenient. To enforce policy on
DNS requests themselves, see :ref:`l7_policy`.

.. note::

	In order to associate domain names with IP addresses, Cilium intercepts
	DNS responses per-Endpoint using a `DNS Proxy`. This requires Cilium
	to be configured with ``--enable-l7-proxy=true`` and an L7 policy allowing
	DNS requests. For more details, see :ref:`DNS Obtaining Data`.

An L3 `CIDR based`_ rule is generated for every ``toFQDNs``
rule and applies to the same endpoints. The IP information is selected for
insertion by ``matchName`` or ``matchPattern`` rules, and is collected from all
DNS responses seen by Cilium on the node. Multiple selectors may be included in
a single egress rule.

.. note:: The DNS Proxy is provided in each Cilium agent.
   As a result, DNS requests targeted by policies depend on the availability
   of the Cilium agent pod.
   This includes DNS policies (:ref:`proxy_visibility`).

``toFQDNs`` egress rules cannot contain any other L3 rules, such as
``toEndpoints`` (under `Endpoints Based`_) and ``toCIDRs`` (under `CIDR Based`_).
They may contain L4/L7 rules, such as ``toPorts`` (see :ref:`l4_policy`)
with, optionally, ``HTTP`` section (see :ref:`l7_policy`).

.. note:: DNS based rules are intended for external connections and behave
          similarly to `CIDR based`_ rules. See `Services based`_ and
          `Endpoints based`_ for cluster-internal traffic.

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
  * ``**.`` is a special prefix supported in DNS match pattern to wildcard all cascaded
    subdomains in the prefix. For example: ``**.cilium.io`` pattern will match both
    ``app.cilium.io`` and ``test.app.cilium.io`` but not ``cilium.io``.

The example below allows all DNS traffic on port 53 to the DNS service and
intercepts it via the `DNS Proxy`. If using a non-standard DNS port for
a DNS application behind a Kubernetes Service, the port must match the backend
port. When the application makes a request for my-remote-service.com, Cilium
learns the IP address and will allow traffic due to the match on the name under
the ``toFQDNs.matchName`` rule.

Example
~~~~~~~

.. literalinclude:: ../../../examples/policies/l3/fqdn/fqdn.yaml
  :language: yaml

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
