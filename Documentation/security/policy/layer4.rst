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
