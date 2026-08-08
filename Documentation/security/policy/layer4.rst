.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _l4_policy:

Layer 4 Policies
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
                // Port can be an L4 port number, or a name in the form of "http"
                // or "http-8080". EndPort is ignored if Port is a named port.
                Port string `json:"port"`

                // EndPort can only be an L4 port number. It is ignored when
                // Port is a named port.
                //
                // +optional
                EndPort int32 `json:"endPort,omitempty"`

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

.. literalinclude:: ../../../examples/policies/l4/l4.yaml
  :language: yaml

Example Port Ranges
~~~~~~~~~~~~~~~~~~~

The following rule limits all endpoints with the label ``app=myService`` to
only be able to emit packets using TCP on ports 80-444, to any layer 3 destination:

.. literalinclude:: ../../../examples/policies/l4/l4_port_range.yaml
  :language: yaml

.. note:: Layer 7 rules support port ranges, except for DNS rules.

Labels-dependent Layer 4 rule
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example enables all endpoints with the label ``role=frontend`` to
communicate with all endpoints with the label ``role=backend``, but they must
communicate using TCP on port 80. Endpoints with other labels will not be
able to communicate with the endpoints with the label ``role=backend``, and
endpoints with the label ``role=frontend`` will not be able to communicate with
``role=backend`` on ports other than 80.

.. literalinclude:: ../../../examples/policies/l4/l3_l4_combined.yaml
  :language: yaml

CIDR-dependent Layer 4 Rule
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example enables all endpoints with the label ``role=crawler`` to
communicate with all remote destinations inside the CIDR ``192.0.2.0/24``, but
they must communicate using TCP on port 80. The policy does not allow Endpoints
without the label ``role=crawler`` to communicate with destinations in the CIDR
``192.0.2.0/24``. Furthermore, endpoints with the label ``role=crawler`` will
not be able to communicate with destinations in the CIDR ``192.0.2.0/24`` on
ports other than port 80.

.. literalinclude:: ../../../examples/policies/l4/cidr_l4_combined.yaml
  :language: yaml

Limit ICMP/ICMPv6 types
-----------------------

ICMP policy can be specified in addition to layer 3 policies or independently.
It restricts the ability of an endpoint to emit and/or receive packets on a
particular ICMP/ICMPv6 type (both type (integer) and corresponding CamelCase message (string) are supported).
If any ICMP policy is specified, layer 4 and ICMP communication will be blocked
unless it's related to a connection that is otherwise allowed by the policy.

ICMP policy can be specified at both ingress and egress using the
``icmps`` field. The ``icmps`` field takes a ``ICMPField`` structure
which is defined as follows:

.. code-block:: go

        // ICMPField is a ICMP field.
        //
        // +deepequal-gen=true
        // +deepequal-gen:private-method=true
        type ICMPField struct {
            // Family is a IP address version.
            // Currently, we support `IPv4` and `IPv6`.
            // `IPv4` is set as default.
            //
            // +kubebuilder:default=IPv4
            // +kubebuilder:validation:Optional
            // +kubebuilder:validation:Enum=IPv4;IPv6
            Family string `json:"family,omitempty"`

	        // Type is a ICMP-type.
	        // It should be an 8bit code (0-255), or it's CamelCase name (for example, "EchoReply").
	        // Allowed ICMP types are:
	        //     Ipv4: EchoReply | DestinationUnreachable | Redirect | Echo | EchoRequest |
	        //		     RouterAdvertisement | RouterSelection | TimeExceeded | ParameterProblem |
	        //			 Timestamp | TimestampReply | Photuris | ExtendedEcho Request | ExtendedEcho Reply
	        //     Ipv6: DestinationUnreachable | PacketTooBig | TimeExceeded | ParameterProblem |
	        //			 EchoRequest | EchoReply | MulticastListenerQuery| MulticastListenerReport |
	        // 			 MulticastListenerDone | RouterSolicitation | RouterAdvertisement | NeighborSolicitation |
	        // 			 NeighborAdvertisement | RedirectMessage | RouterRenumbering | ICMPNodeInformationQuery |
	        // 			 ICMPNodeInformationResponse | InverseNeighborDiscoverySolicitation | InverseNeighborDiscoveryAdvertisement |
	        // 			 HomeAgentAddressDiscoveryRequest | HomeAgentAddressDiscoveryReply | MobilePrefixSolicitation |
	        // 			 MobilePrefixAdvertisement | DuplicateAddressRequestCodeSuffix | DuplicateAddressConfirmationCodeSuffix |
	        // 			 ExtendedEchoRequest | ExtendedEchoReply
	        //
	        // +deepequal-gen=false
	        // +kubebuilder:validation:XIntOrString
	        // +kubebuilder:validation:Pattern="^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|EchoReply|DestinationUnreachable|Redirect|Echo|RouterAdvertisement|RouterSelection|TimeExceeded|ParameterProblem|Timestamp|TimestampReply|Photuris|ExtendedEchoRequest|ExtendedEcho Reply|PacketTooBig|ParameterProblem|EchoRequest|MulticastListenerQuery|MulticastListenerReport|MulticastListenerDone|RouterSolicitation|RouterAdvertisement|NeighborSolicitation|NeighborAdvertisement|RedirectMessage|RouterRenumbering|ICMPNodeInformationQuery|ICMPNodeInformationResponse|InverseNeighborDiscoverySolicitation|InverseNeighborDiscoveryAdvertisement|HomeAgentAddressDiscoveryRequest|HomeAgentAddressDiscoveryReply|MobilePrefixSolicitation|MobilePrefixAdvertisement|DuplicateAddressRequestCodeSuffix|DuplicateAddressConfirmationCodeSuffix)$"
            Type *intstr.IntOrString `json:"type"`
        }

Example (ICMP/ICMPv6)
~~~~~~~~~~~~~~~~~~~~~

The following rule limits all endpoints with the label ``app=myService`` to
only be able to emit packets using ICMP with type 8 and ICMPv6 with message EchoRequest,
to any layer 3 destination:

.. literalinclude:: ../../../examples/policies/l4/icmp.yaml
  :language: yaml

Limit TLS Server Name Indication (SNI)
--------------------------------------

When multiple websites are hosted on the same server with a shared IP address,
Server Name Indication (SNI), an extension of the TLS protocol, ensures that
the client receives the correct SSL certificate for the website they are
trying to access. SNI allows the hostname or domain name of the website to be
specified during the TLS handshake, rather than after the handshake when the
HTTP connection is established.

Cilium Network Policy can limit an endpoint's ability to establish a TLS
handshake to a specified list of SNIs. The SNI policy is always configured
at the egress level and is usually set up alongside port policies.

Example (TLS SNI)
~~~~~~~~~~~~~~~~~

.. note:: TLS SNI policy enforcement requires L7 proxy enabled.

The following rule limits all endpoints with the label ``app=myService`` to
only be able to establish TLS connections with ``one.one.one.one`` SNI. Any
other attempt to another SNI (for example, with ``cilium.io``) will be rejected.

.. literalinclude:: ../../../examples/policies/l4/l4_sni.yaml
  :language: yaml

Below is the same SSL error while trying to connect to ``cilium.io`` from curl.

.. code-block:: shell-session

    $ kubectl exec <my-service-pod> -- curl -v https://cilium.io
    * Host cilium.io:443 was resolved.
    * IPv6: (none)
    * IPv4: 104.198.14.52
    *   Trying 104.198.14.52:443...
    * Connected to cilium.io (104.198.14.52) port 443
    * ALPN: curl offers h2,http/1.1
    * TLSv1.3 (OUT), TLS handshake, Client hello (1):
    *  CAfile: /etc/ssl/certs/ca-certificates.crt
    *  CApath: /etc/ssl/certs
    * Recv failure: Connection reset by peer
    * OpenSSL SSL_connect: Connection reset by peer in connection to cilium.io:443
    * Closing connection
    curl: (35) Recv failure: Connection reset by peer
    command terminated with exit code 35

.. _envoy_listener_redirect:

Redirect traffic to an Envoy listener
-------------------------------------

A ``toPorts`` rule can carry a ``listener`` reference that redirects matching
traffic to a named Envoy listener defined in a CiliumEnvoyConfig (CEC) or
CiliumClusterwideEnvoyConfig (CCEC). Instead of allowing or denying the traffic,
Cilium hands the traffic to the Envoy proxy, where the listener can act on the
traffic, for example to manipulate headers, route, rewrite, or observe requests.

.. warning::

   A ``listener`` redirect offers a lot of flexibility, but it requires writing
   raw Envoy configuration inside the CiliumEnvoyConfig or
   CiliumClusterwideEnvoyConfig resource. Cilium performs only minimal validation
   on that configuration, so small mistakes are easy to make and hard to debug.
   Prefer solving traffic-management use cases with the higher-level Cilium
   Gateway API support, including :ref:`GAMMA <gs_gamma>` for mesh (east-west)
   traffic, and only reach for a ``listener`` redirect when the Gateway API does
   not cover the use case. See :ref:`gs_gateway_api` and :ref:`gs_gamma`.

Configure the ``listener`` field on egress, alongside the ``ports`` inside a
``toPorts`` entry. The ``listener`` field contains the following keys:

* ``envoyConfig`` — references the CEC or CCEC that defines the listener, using
  the ``kind`` and ``name`` keys. When ``kind`` is omitted, Cilium resolves the
  reference within the policy's own scope: a CiliumNetworkPolicy looks for a
  namespaced CiliumEnvoyConfig in its own namespace, and a
  CiliumClusterwideNetworkPolicy looks for a cluster-scoped
  CiliumClusterwideEnvoyConfig. Setting ``kind`` explicitly states which resource
  type defines the listener. A CiliumNetworkPolicy can reference either a
  CiliumEnvoyConfig in its namespace or, by setting
  ``kind: CiliumClusterwideEnvoyConfig``, a cluster-scoped
  CiliumClusterwideEnvoyConfig. A CiliumClusterwideNetworkPolicy can only
  reference a CiliumClusterwideEnvoyConfig.
* ``name`` — the name of the listener within that config.

The following examples use CiliumNetworkPolicy, but the same ``listener`` field
works the same way in a CiliumClusterwideNetworkPolicy.

.. note::

   A ``listener`` redirect cannot be combined with Layer 7 ``rules`` (HTTP or
   DNS) in the same ``toPorts`` entry. Use the Envoy listener itself to express
   any application-layer behavior.

For how to define the listener and the supporting Envoy resources, see
:ref:`gs_l7_traffic_management` and :ref:`gs_envoy_custom_listener`.

Example (redirect to Envoy)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following rule allows all endpoints with the label ``app=myService`` to
emit HTTP traffic to ``example.com`` on TCP port 80, and redirects that traffic
to the Envoy listener ``add-header-listener``:

.. literalinclude:: ../../../examples/policies/l4/envoy_listener_redirect.yaml
  :language: yaml
  :emphasize-lines: 16-20

A separate CiliumClusterwideEnvoyConfig defines the referenced listener. The
following minimal listener injects an ``X-Request-Source: cilium`` request
header before forwarding the request upstream:

.. literalinclude:: ../../../examples/policies/l4/envoy_listener_redirect_cec.yaml
  :language: yaml

The route sends matching requests to ``original-dst-cluster``, an
``ORIGINAL_DST`` cluster defined in the same CiliumClusterwideEnvoyConfig. The
cluster forwards each connection to the original destination of the request
(``example.com`` in this example) after adding the header.

The names in the policy must match the names in the CiliumClusterwideEnvoyConfig:

* ``envoyConfig.name`` in the policy (``add-header-config``) matches the
  ``metadata.name`` of the CiliumClusterwideEnvoyConfig.
* ``name`` in the policy (``add-header-listener``) matches the ``name`` of the
  listener resource inside that CiliumClusterwideEnvoyConfig.

The config sets the annotation
``cec.cilium.io/use-original-source-address: "false"``. This annotation controls
the source address Envoy uses for the upstream connection. For a hand-written
CiliumEnvoyConfig or CiliumClusterwideEnvoyConfig, the annotation defaults to
``"true"``, which keeps the original pod source address (transparent proxy). For
pod-originated egress redirects like this example, set it to
``"false"`` so that Envoy uses its own source address. With the
default ``"true"``, Cilium binds the upstream socket to the intercepted
connection's source IP and port, then connects to the same destination via the
``ORIGINAL_DST`` cluster. The resulting upstream 5-tuple (source IP, source
port, destination IP, destination port, protocol) is identical to the
intercepted downstream connection that is still open. The kernel rejects the
duplicate and the connection fails. Setting ``"false"`` lets Envoy pick a fresh
source address for the upstream connection, which keeps every 5-tuple unique.

.. note::

   The Cilium Envoy proxy ships with a curated subset of Envoy extensions, not
   the full set. Before relying on a particular filter or extension, confirm
   that the proxy build includes it. The enabled extensions are listed in the
   `Envoy extensions build configuration`_. Check the Cilium version you run and
   read the configuration for that version, because the set of enabled
   extensions changes over time.

.. _Envoy extensions build configuration: https://github.com/cilium/proxy/blob/main/envoy_build_config/extensions_build_config.bzl

Example (forward proxy with authentication)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

One use of an Envoy listener redirect routes egress traffic through an external
HTTP forward proxy and injects the credentials that the forward proxy requires.
The Envoy listener tunnels the redirected TCP connection through the forward
proxy and adds a ``Proxy-Authorization`` header, so the application pods do not
need to be aware of the forward proxy or hold the forward proxy's credentials.

The following policy redirects internet-bound web traffic on port 80 to the
Envoy listener. The ``toCIDRSet`` selector matches every destination except the
private (RFC 1918) ranges, so cluster-local and private-network traffic is not
redirected:

.. literalinclude:: ../../../examples/policies/l4/envoy_forward_proxy.yaml
  :language: yaml
  :emphasize-lines: 23-27

The listener uses a TCP proxy with a ``tunneling_config`` that adds the
``Proxy-Authorization`` header and forwards the connection to the external
forward proxy at ``10.0.100.10:3128``:

.. literalinclude:: ../../../examples/policies/l4/envoy_forward_proxy_cec.yaml
  :language: yaml

.. note::

   The example encodes static Basic credentials for illustration, which means
   the credentials live in plain text inside the CiliumClusterwideEnvoyConfig.
   The ``headers_to_add`` field of the TCP proxy ``tunneling_config`` accepts
   only literal values; it cannot reference a Kubernetes secret or an Envoy
   Secret Discovery Service (SDS) secret. Anyone who can read the
   CiliumClusterwideEnvoyConfig can therefore read the credentials, so restrict
   access to the resource with RBAC and treat it as sensitive. To keep
   credentials out of the configuration entirely, the listener must be
   redesigned around a filter that supports SDS, which is beyond the scope of
   this example.

Wildcard port
~~~~~~~~~~~~~

Setting ``port: "0"`` acts as a wildcard, matching all ports for the given
protocol. A single rule then applies to every port without enumerating each
port.

Wildcard ports pair well with a transport-level Envoy listener such as the
forward-proxy listener in the preceding example. Because a TCP-proxy listener
operates on the connection rather than parsing an application protocol, the
listener handles traffic on any port. Setting the port to ``"0"`` sends all egress TCP
connections through the forward proxy, instead of limiting the redirect to a
single port such as 80.

The following rule redirects all internet-bound TCP egress traffic through the
forward-proxy listener. The ``toCIDRSet`` selector matches every destination
address except the private (RFC 1918) ranges, so traffic that stays inside the
cluster or the local network is not redirected:

.. literalinclude:: ../../../examples/policies/l4/wildcard_port_listener.yaml
  :language: yaml
  :emphasize-lines: 20

.. note::

   ``port: "0"`` cannot be combined with Layer 7 ``rules`` (HTTP or DNS);
   ``port: "0"`` is a Layer 3/4 construct.
