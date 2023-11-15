.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bgp_control_plane:

Cilium BGP Control Plane (Beta)
===============================

BGP Control Plane provides a way for Cilium to advertise routes to connected routers by using the
`Border Gateway Protocol`_ (BGP). BGP Control Plane makes Pod networks and/or Services of type
``LoadBalancer`` reachable from outside the cluster for environments that support BGP. Because BGP
Control Plane does not program the :ref:`datapath <ebpf_datapath>`, do not use it to establish
reachability within the cluster.

.. _Border Gateway Protocol: https://datatracker.ietf.org/doc/html/rfc4271

Usage
-----

Currently a single flag in the ``Cilium Agent`` exists to turn on the
``BGP Control Plane`` feature set.

::

   --enable-bgp-control-plane=true

If using Helm charts instead, the relevant values are the following:

.. code-block:: yaml

   bgpControlPlane:
     enabled: true

.. note::

   The BGP Control Plane feature is mutually exclusive with the MetalLB-based :ref:`bgp`
   feature. To use the Control Plane, the older BGP feature has to be disabled.
   In other words, this feature does _not_ switch the BGP implementation
   from MetalLB to GoBGP.

When set to ``true`` the ``BGP Control Plane`` ``Controllers`` will be
instantiated and will begin listening for ``CiliumBGPPeeringPolicy``
events.

Currently, the ``BGP Control Plane`` will only work when IPAM mode is set to
"cluster-pool", "kubernetes", or "multi-pool".

CiliumBGPPeeringPolicy CRD
~~~~~~~~~~~~~~~~~~~~~~~~~~

All ``BGP`` peering topology information is carried in a
``CiliumBGPPeeringPolicy`` CRD.

``CiliumBGPPeeringPolicy`` can be applied to one or more nodes based on
its ``nodeSelector`` fields.

A Cilium node may only have a single ``CiliumBGPPeeringPolicy`` apply to
it and if more than one does, it will apply no policy at all.

Each ``CiliumBGPPeeringPolicy`` defines one or more
``CiliumBGPVirtualRouter`` configurations.

When these CRDs are written or read from the cluster the ``Controllers``
will take notice and perform the necessary actions to drive the
``BGP Control Plane`` to the desired state described by the policy.

The policy in ``yaml`` form is defined below:

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
    name: 01-bgp-peering-policy
   spec: # CiliumBGPPeeringPolicySpec
    nodeSelector:
      matchLabels:
        bgp-policy: a
    virtualRouters: # []CiliumBGPVirtualRouter
    - localASN: 64512
      exportPodCIDR: true
      neighbors: # []CiliumBGPNeighbor
       - peerAddress: 'fc00:f853:ccd:e793::50/128'
         peerASN: 64512
         eBGPMultihopTTL: 10
         connectRetryTimeSeconds: 120
         holdTimeSeconds: 90
         keepAliveTimeSeconds: 30
         gracefulRestart:
           enabled: true
           restartTimeSeconds: 120

Fields
^^^^^^

::

   nodeSelector: Nodes which are selected by this label selector will apply the given policy

    virtualRouters: One or more peering configurations outlined below. Each peering configuration can be thought of as a BGP router instance.

       virtualRouters[*].localASN: The local ASN for this peering configuration

       virtualRouters[*].serviceSelector: Services which are selected by this label selector will be announced.

       virtualRouters[*].podIPPoolSelector: Allocated CIDRs from CiliumPodIPPools which are selected by this label selector will be announced.

       virtualRouters[*].exportPodCIDR: Whether to export the private pod CIDR block to the listed neighbors

       virtualRouters[*].neighbors: A list of neighbors to peer with
           neighbors[*].peerAddress: The address of the peer neighbor
           neighbors[*].peerPort: Optional TCP port number of the neighbor. 1-65535 are valid values and defaults to 179 when unspecified.
           neighbors[*].peerASN: The ASN of the peer
           neighbors[*].authSecretRef: Optional name of a secret in the BGP secrets namespace to use to retrieve a TCP MD5 password.
           neighbors[*].eBGPMultihopTTL: Time To Live (TTL) value used in BGP packets. The value 1 implies that eBGP multi-hop feature is disabled.
           neighbors[*].connectRetryTimeSeconds: Initial value for the BGP ConnectRetryTimer (RFC 4271, Section 8). Defaults to 120 seconds.
           neighbors[*].holdTimeSeconds: Initial value for the BGP HoldTimer (RFC 4271, Section 4.2). Defaults to 90 seconds.
           neighbors[*].keepAliveTimeSeconds: Initial value for the BGP KeepaliveTimer (RFC 4271, Section 8). Defaults to 30 seconds.
           neighbors[*].gracefulRestart.enabled: The flag to enable graceful restart capability.
           neighbors[*].gracefulRestart.restartTimeSeconds: The restart time advertised to the peer (RFC 4724 section 4.2).

.. note::

   Setting unique configuration details of a particular
   instantiated virtual router on a particular Cilium node is explained
   in `Virtual Router Attributes`_

Creating a BGP Topology
-----------------------

Rules
~~~~~

Follow the rules below to have a ``CiliumBGPPeeringPolicy`` correctly
apply to a node.

-  Only a single ``CiliumBGPPeeringPolicy`` can apply to a ``Cilium``
   node.

   -  If the ``BGP Control Plane`` on a node iterates through the
      ``CiliumBGPPeeringPolicy`` CRs currently written to the cluster
      and discovers (n > 1) policies match its labels, it will return an
      error and remove any existing BGP sessions. Only (n == 1) policies
      **must** match a node's label sets.
   -  Administrators should test a new BGP topology in a staging
      environment before making permanent changes in production.

-  Within a ``CiliumBGPPeeringPolicy`` each ``CiliumBGPVirtualRouter``
   defined must have a unique ``localASN`` field.

   -  A node cannot host two or more logical routers with the same local
      ASN. Local ASNs are used as unique keys for a logical router.
   -  A node can define the remote ASN on a per-neighbor basis to
      mitigate this scenario. See ``CiliumBGPNeighbor`` CR
      sub-structure.

-  IPv6 single stack deployments **must** set an IPv4 encoded
   ``routerID`` field in each defined ``CiliumBGPVirtualRouter`` object
   within a ``CiliumBGPPeeringPolicy``

   -  Cilium running on a IPv6 single stack cluster cannot reliably
      generate a unique 32 bit BGP router ID, as it defines no unique
      IPv4 addresses for the node. The administrator must define these
      IDs manually or an error applying the policy will occur.
   -  This is explained further in `Virtual Router Attributes`_

Defining Topology
~~~~~~~~~~~~~~~~~

Within a ``CiliumBGPPeeringPolicy`` multiple
``CiliumBGPVirtualRouter``\ (s) can be defined.

Each one can be thought of as a logical BGP router instance.

Defining more than one ``CiliumBGPVirtualRouter`` in a
``CiliumBGPVirtualRouter`` creates more than one logical BGP router on
the hosts which the policy matches.

It is possible to create a single ``CiliumBGPPeeringPolicy`` for all
nodes by giving each node in a cluster the same label and defining a
single ``CiliumBGPPeeringPolicy`` which applies to this label.

It is also possible to provide each ``Kubernetes`` node its own
``CiliumBGPPeeringPolicy`` by giving each node a unique label and
creating a ``CiliumBGPPeeringPolicy`` for each unique label.

This allows for selecting subsets of nodes which peer to a particular
BGP router while another subset of nodes peer to a separate BGP router,
akin to an "AS-per-rack" topology.

Virtual Router Attributes
~~~~~~~~~~~~~~~~~~~~~~~~~

A ``CiliumBGPPeeringPolicy`` can apply to multiple nodes.

When a ``CiliumBGPPeeringPolicy`` applies to one or more nodes each node
will instantiate one or more BGP routers as defined by the list of
``CiliumBGPVirutalRouter``.

However, there are times where fine-grained control over an instantiated
virtual router's configuration needs to take place.

To accomplish this a Kubernetes annotation is defined which applies to
Kubernetes Node resources.

A single annotation is used to specify a set of configuration attributes
to apply to a particular virtual router instantiated on a particular
host.

The syntax of the annotation is as follows:

::

       cilium.io/bgp-virtual-router.{asn}="key=value,..."

The ``{asn}`` portion should be replaced by the virtual router's local
ASN you wish to apply these configuration attributes to.

The following sections outline the currently supported attributes.

.. note::

   Each following section describes the syntax of applying a
   single attribute, however the annotation's value supports a comma
   separated lists of attributes and applying multiple attributes in a
   single annotation is supported.

.. note::

   When duplicate ``key=value`` attributes are defined the last
   one will be selected.

Router ID Attribute
^^^^^^^^^^^^^^^^^^^

When Cilium is running on an ``IPv4`` or a dual-stack ``IPv4/6`` cluster
the ``BGP Control Plane`` will utilize the ``IPv4`` addressed used by
Cilium for external reach ability.

This will typically be Kubernetes' reported external IP address but can
also be configured with a Cilium agent flag.

When running in ``IPv6`` single stack or when the administrator needs to
manually define the instantiated BGP server's router ID a Kubernetes
annotation can be placed on the node.

The annotation takes the following syntax:

::

   cilium.io/bgp-virtual-router.{asn}="router-id=127.0.0.1"

The above annotation syntax should replace ``{asn}`` with the local ASN
of the ``CiliumBGPVirtualRouter`` you are setting the provided router ID
for.

When the ``BGPControlPlane`` evaluates a ``CiliumBGPPeeringPolicy`` with
a ``CiliumBGPVirtualRouter`` it also searches for an annotation which
targets the aforementioned ``CiliumBGPVirtualRouter`` local ASN.

If found it will use the provided router ID and not attempt to use the
IPv4 address assigned to the node.

Local Listening Port
^^^^^^^^^^^^^^^^^^^^

By default the ``GoBGP BGPRouterManager`` will instantiate each virtual
router without a listening port.

It is possible to deploy a virtual router which creates a local
listening port where BGP connections may take place.

If this is desired the following annotation can be provided

::

   cilium.io/bgp-virtual-router.{asn}="local-port=45450"

Neighbors
^^^^^^^^^

Each ``CiliumBGPVirtualRouter`` can contain multiple ``CiliumBGPNeighbor`` sections,
each specifying configuration for a neighboring BGP peer of the Virtual Router.
Each neighbor is uniquely identified by the address and the ASN of the peer, and can
contain additional configuration specific for the given BGP peering, such as BGP timer
values, graceful restart configuration and others.

.. warning::

   Change of an existing neighbor configuration can cause reset of the existing BGP
   peering connection, which results in route flaps and transient packet loss while
   the session reestablishes and peers exchange their routes. To prevent packet loss,
   it is recommended to configure BGP graceful restart.

MD5 passwords
'''''''''''''

By configuring ``authSecretRef`` for a neighbor you can configure that a
`RFC-2385`_ TCP MD5 password should be configured on the session with this BGP
peer.

``authSecretRef`` should reference the name of a secret in the BGP secrets
namespace (if using the Helm chart this is ``cilium-bgp-secrets`` by default).
The secret should contain a key with a name of ``password``.

BGP secrets are limited to a configured namespace to keep the permissions
needed on each Cilium Agent instance to a minimum. The Helm chart will create
this namespace and configure Cilium to be able to read from it by default.

An example of creating a secret is:

.. code-block:: shell-session

  # kubectl create secret generic -n cilium-bgp-secrets --type=string secretName --from-literal=password=my-secret-password

Because TCP MD5 passwords sign the header of the packet they cannot be used if
the session will be address translated by Cilium (i.e. the Cilium Agent's pod
IP address must be the address the BGP peer sees).

If the password is incorrect, or the header is otherwise changed the TCP
connection will not succeed. This will appear as ``dial: i/o timeout`` in the
Cilium Agent's logs rather than a more specific error message.

.. _RFC-2385 : https://www.rfc-editor.org/rfc/rfc2385.html

Graceful Restart
''''''''''''''''
The Cilium BGP control plane can be configured to act as a graceful restart
``Restarting Speaker``. When you enable graceful restart, the BGP session will restart
and the "graceful restart" capability will be advertised in the BGP OPEN message.

In the event of a Cilium Agent restart, the peering BGP router does not withdraw
routes received from the Cilium BGP control plane immediately. The datapath
continues to forward traffic during Agent restart, so there is no traffic
disruption.

Configure graceful restart on per-neighbor basis, as follows:

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   #[...]
   virtualRouters: # []CiliumBGPVirtualRouter
    - localASN: 64512
      # [...]
      neighbors: # []CiliumBGPNeighbor
       - peerAddress: 'fc00:f853:ccd:e793::50/128'
         # [...]
         gracefulRestart:
           enabled: true
           restartTimeSeconds: 120

.. note::

   When enabled, graceful restart capability is advertised for IPv4 and IPv6 address families.

Optionally, you can use the ``RestartTime`` parameter. ``RestartTime`` is the time
advertised to the peer within which Cilium BGP control plane is expected to re-establish
the BGP session after a restart. On expiration of ``RestartTime``, the peer removes
the routes previously advertised by the Cilium BGP control plane.

When the Cilium Agent restarts, it closes the BGP TCP socket, causing the emission of a
TCP FIN packet. On receiving this TCP FIN, the peer changes its BGP state to ``Idle`` and
starts its ``RestartTime`` timer.

The Cilium agent boot up time varies depending on the deployment. If using ``RestartTime``,
you should set it to a duration greater than the time taken by the Cilium Agent to boot up.

Default value of ``RestartTime`` is 120 seconds. More details on graceful restart and
``RestartTime`` can be found in `RFC-4724`_ and `RFC-8538`_.

.. _RFC-4724 : https://www.rfc-editor.org/rfc/rfc4724.html
.. _RFC-8538 : https://www.rfc-editor.org/rfc/rfc8538.html

Advertised Path Attributes
''''''''''''''''''''''''''

BGP advertisements can be extended with additional BGP Path Attributes - BGP Communities (`RFC-1997`_) or Local Preference.
These Path Attributes can be configured selectively for each BGP peer and advertisement type.

The following code block shows an example configuration of ``AdvertisedPathAttributes`` for a BGP neighbor,
which adds a BGP community attribute with the value ``65001:100`` to all Service announcements from the
matching ``CiliumLoadBalancerIPPool`` and sets the Local Preference value for all Pod CIDR announcements
to the value ``150``:

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   #[...]
   virtualRouters: # []CiliumBGPVirtualRouter
    - localASN: 64512
      # [...]
      neighbors: # []CiliumBGPNeighbor
       - peerASN: 64512
         peerAddress: 172.0.0.1/32
         # [...]
         advertisedPathAttributes:
         - selectorType: CiliumLoadBalancerIPPool
           selector:
             matchLabels:
               environment: production
           communities:
             standard:
             - 65001:100
         - selectorType: PodCIDR
           localPreference: 150
           communities:
             standard:
             - 65001:150

.. note::
  Note that Local Preference Path Attribute is sent only to ``iBGP`` peers (not to ``eBGP`` peers).

Each ``AdvertisedPathAttributes`` configuration item consists of two parts:

 - ``SelectorType`` with ``Selector`` define which BGP advertisements will be extended with additional Path Attributes.
 - ``Communities`` and / or ``LocalPreference`` define the additional Path Attributes applied on the selected routes.

There are three possible values of the ``SelectorType`` which define the object type on which the ``Selector`` applies:

 - ``PodCIDR``: matches ``CiliumNode`` custom resources
   (Path Attributes apply to routes announced for PodCIDRs of selected ``CiliumNode`` objects).
 - ``CiliumLoadBalancerIPPool``: matches ``CiliumLoadBalancerIPPool`` custom resources
   (Path Attributes apply to routes announced for selected ``CiliumLoadBalancerIPPool`` objects).
 - ``CiliumPodIPPool``: matches ``CiliumPodIPPool`` custom resources
   (Path Attributes apply to routes announced for allocated prefixes of selected ``CiliumPodIPPool`` objects).

There are two types of additional Path Attributes that can be advertised with the routes: ``Communities`` and ``LocalPreference``.

``Communities`` defines a set of community values advertised in the supported BGP Communities Path Attributes.
The values can be of two types:

 - ``Standard``: represents a value of the "standard" 32-bit BGP Communities Attribute (`RFC-1997`_)
   as a 4-byte decimal number or two 2-byte decimal numbers separated by a colon (e.g. ``65100:100``).
 - ``Large``: represents a value of the BGP Large Communities Attribute (`RFC-8092`_),
   as three 4-byte decimal numbers separated by colons (e.g. ``65100:100:50``).

.. _RFC-1997 : https://www.rfc-editor.org/rfc/rfc1997.html
.. _RFC-8092 : https://www.rfc-editor.org/rfc/rfc8092.html

``LocalPreference`` defines the preference value advertised in the BGP Local Preference Path Attribute.
As Local Preference is only valid for ``iBGP`` peers, this value will be ignored for ``eBGP`` peers
(no Local Preference Path Attribute will be advertised).

Once configured, the additional Path Attributes advertised with the routes for a peer can be verified using the
``cilium-dbg bgp routes`` CLI command, for example:

.. code-block:: shell-session

   $ cilium-dbg bgp routes advertised ipv4 unicast peer 172.0.0.1

   VRouter   Prefix               NextHop     Age     Attrs
   65000     10.244.0.0/24        172.0.0.2   3m31s   [{Origin: i} {LocalPref: 150} {Nexthop: 172.0.0.2}
   65000     192.168.100.190/32   172.0.0.2   3m32s   [{Origin: i} {LocalPref: 100} {Communities: 64512:100}] {Nexthop: 172.0.0.2}


Service announcements
---------------------

By default, virtual routers will not announce services. Virtual routers will announce
the ingress IPs of any LoadBalancer services that matches the ``.serviceSelector``
of the virtual router and has `loadBalancerClass <https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class>`__
unspecified or set to ``io.cilium/bgp-control-plane``.

If you wish to announce ALL services within the cluster, a ``NotIn`` match expression
with a dummy key and value can be used like:

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   #[...]
   virtualRouters: # []CiliumBGPVirtualRouter
    - localASN: 64512
      # [...]
      serviceSelector:
         matchExpressions:
            - {key: somekey, operator: NotIn, values: ['never-used-value']}

There are a few special purpose selector fields which don't match on labels but
instead on other metadata like ``.meta.name`` or ``.meta.namespace``.

=============================== ===================
Selector                        Field
------------------------------- -------------------
io.kubernetes.service.namespace ``.meta.namespace``
io.kubernetes.service.name      ``.meta.name``
=============================== ===================

Semantics of the externalTrafficPolicy: Local
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the service has ``externalTrafficPolicy: Local``, ``BGP Control Plane`` keeps track
of the endpoints for the service on the local node and stops advertisement when there's
no local endpoint.

CiliumPodIPPool announcements
-----------------------------

By default, virtual routers will not announce any CiliumPodIPPool CIDRs. To announce allocated
CIDRs of a CiliumPodIPPool, specify the ``.podIPPoolSelector`` for the virtual router. The
``.podIPPoolSelector`` field is a label selector that selects allocated CIDRs of CiliumPodIPPools
matching the specified ``.matchLabels`` or ``.matchExpressions``.

.. note::

   The CiliumPodIPPool CIDR must be allocated to a CiliumNode that matches the ``.nodeSelector`` for
   the virtual router to announce the CIDR as a BGP route.

If you wish to announce ALL CiliumPodIPPool CIDRs within the cluster, a ``NotIn`` match expression
with a dummy key and value can be used like:

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   #[...]
   virtualRouters: # []CiliumBGPVirtualRouter
    - localASN: 64512
      # [...]
      podIPPoolSelector:
         matchExpressions:
            - {key: somekey, operator: NotIn, values: ['never-used-value']}

There are two special purpose selector fields that match CiliumPodIPPools based on ``name`` and/or
``namespace`` metadata instead of labels:

=============================== ===================
Selector                        Field
------------------------------- -------------------
io.cilium.podippool.namespace   ``.meta.namespace``
io.cilium.podippool.name        ``.meta.name``
=============================== ===================

For additional details regarding CiliumPodIPPools, see the :ref:`ipam_crd_multi_pool` section.

CLI
---

There are two CLIs available to view cilium BGP peering state. One CLI is present
inside Cilium Agent. The second CLI is the cluster-wide `Cilium CLI <https://github.com/cilium/cilium-cli>`_.

.. warning::

   The Cilium CLI is experimental. Consider carefully before using it in production environments!

Cilium Agent CLI
~~~~~~~~~~~~~~~~

The following command shows peering status:

.. code-block:: shell-session

   cilium# cilium-dbg bgp peers -h
   List state of all peers defined in CiliumBGPPeeringPolicy

   Usage:
     cilium-dbg bgp peers [flags]

   Flags:
     -h, --help            help for peers
     -o, --output string   json| yaml| jsonpath='{}'

   Global Flags:
         --config string   Config file (default is $HOME/.cilium.yaml)
     -D, --debug           Enable debug messages
     -H, --host string     URI to server-side API

The following command shows BGP routes available in the RIB / advertised to the peers:

.. code-block:: shell-session

   cilium# cilium-dbg bgp routes -h
   List routes in the BGP Control Plane's Routing Information Bases (RIBs)

   Usage:
     cilium-dbg bgp routes <available | advertised> <afi> <safi> [vrouter <asn>] [peer|neighbor <address>] [flags]

   Examples:
     Get all IPv4 unicast routes available:
       cilium bgp routes available ipv4 unicast

     Get all IPv6 unicast routes available for a specific vrouter:
       cilium bgp routes available ipv6 unicast vrouter 65001

     Get IPv4 unicast routes advertised to a specific peer:
       cilium bgp routes advertised ipv4 unicast peer 10.0.0.1

   Flags:
     -h, --help            help for routes
     -o, --output string   json| yaml| jsonpath='{}'

   Global Flags:
         --config string   Config file (default is $HOME/.cilium.yaml)
     -D, --debug           Enable debug messages
     -H, --host string     URI to server-side API

Cilium-CLI
~~~~~~~~~~

Cilium CLI displays the BGP peering status of all nodes.

.. code-block:: shell-session

   # cilium bgp peers -h
   Gets BGP peering status from all nodes in the cluster

   Usage:
     cilium bgp peers [flags]

   Flags:
         --agent-pod-selector string   Label on cilium-agent pods to select with (default "k8s-app=cilium")
     -h, --help                        help for peers
         --node string                 Node from which BGP status will be fetched, omit to select all nodes
     -o, --output string               Output format. One of: json, summary (default "summary")
         --wait-duration duration      Maximum time to wait for result, default 1 minute (default 1m0s)

   Global Flags:
         --context string     Kubernetes configuration context
     -n, --namespace string   Namespace Cilium is running in (default "kube-system")

Architecture
------------

The ``BGP Control Plane`` is split into a ``Agent-Side Control Plane``
and a ``Operator-Side`` control plane (not yet implemented).

Both control planes are implemented by a ``Controller`` which follows
the ``Kubernetes`` controller pattern.

Both control planes primarily listen for ``CiliumBGPPeeringPolicy`` CRDs,
along with other Cilium and Kubernetes resources used for implementing
a BGP control plane.

Agent-Side Architecture
~~~~~~~~~~~~~~~~~~~~~~~

At a high level, the ``Agent-Side Control Plane`` is divided into the following
sub-modules:

- Agent
- Manager
- Router


Agent
^^^^^

The ``Agent`` implements a controller located in ``pkg/bgpv1/agent/controller.go``.

The controller listens for ``CiliumBGPPeeringPolicy`` changes and
determines if the policy applies to its current host.
It will then capture some information about Cilium's current state
and pass down the desired state to ``Manager``.

Manager
^^^^^^^

The ``Manager`` implements the interface ``BGPRouterManager``, which
defines a declarative API between the ``Controller`` and instances of
BGP routers.

The interface defines a single declarative method whose argument is the
desired ``CiliumBGPPeeringPolicy`` (among a few others).

The ``Manager`` is in charge of pushing the ``BGP Control Plane``
to the desired ``CiliumBGPPeeringPolicy`` or returning an error if it
is not possible.

Implementation Details
''''''''''''''''''''''

``Manager`` implementation will take desired ``CiliumBGPPeeringPolicy``
and translate into imperative router API calls :

-  evaluate the desired ``CiliumBGPPeeringPolicy``
-  create/remove the desired BGP routers
-  advertise/withdraw the desired BGP routes
-  enable/disable any BGP server specific features
-  inform the caller if the policy cannot be applied

The ``Manager`` evaluates each ``CiliumBGPVirtualRouter`` in isolation.
While applying a ``CiliumBGPPeeringPolicy``, it will attempt to create each
``CiliumBGPVirtualRouter``.

If a particular ``CiliumBGPVirtualRouter`` fails to instantiate, the error
message is logged, and the ``Manager`` will continue to the next
``CiliumBGPVirtualRouter``.

It is worth expanding on how the ``Manager`` works internally.
``Manager`` views each ``CiliumBGPVirtualRouter`` as a BGP router instance.
Each ``CiliumBGPVirtualRouter`` is defined by a local ASN, a router ID and a
list of ``CiliumBGPNeighbors`` with whom it will establish peering.

This is enough for the ``Manager`` to create a ``Router`` instance.
``Manager`` groups ``Router`` instances by their local ASNs.

.. note::

   A ``CiliumBGPPeeringPolicy`` applying to a node must not have two or more
   ``CiliumBGPVirtualRouters`` with the same ``localASN`` fields.

The ``Manager`` employs a set of ``Reconcilers`` which perform an
order-dependent reconciliation action for each ``Router``.


See the source code at ``pkg/bgpv1/manager/reconcile.go`` for a more in
depth explanation on how each ``Reconcilers`` works.

Router
^^^^^^

``BGP Control Plane`` utilizes ``GoBGP`` as the underlying routing agent.

GoBGP client-side implementation is located in ``pkg/bgpv1/gobgp``.
Implementation API adheres to the ``Router`` interface defined in ``pkg/bgpv1/types/bgp.go``.

