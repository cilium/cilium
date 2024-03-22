.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bgp_control_plane:

Cilium BGP Control Plane
========================

BGP Control Plane provides a way for Cilium to advertise routes to connected routers by using the
`Border Gateway Protocol`_ (BGP). BGP Control Plane makes Pod networks and/or Services reachable
from outside the cluster for environments that support BGP. Because BGP
Control Plane does not program the :ref:`datapath <ebpf_datapath>`, do not use it to establish
reachability within the cluster.

.. _Border Gateway Protocol: https://datatracker.ietf.org/doc/html/rfc4271

Prerequisites
-------------

- If you are using the older MetalLB-based :ref:`bgp` feature, it must be disabled.

Installation
------------

.. tabs::

  .. group-tab:: Helm

        Cilium BGP Control Plane can be enabled with Helm flag ``bgpControlPlane.enabled``
        set as true.

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
                --namespace kube-system \\
                --reuse-values \\
                --set bgpControlPlane.enabled=true
            $ kubectl -n kube-system rollout restart ds/cilium

  .. group-tab:: Cilium CLI

        .. include:: ../installation/cli-download.rst

        Cilium BGP Control Plane can be enabled with the following command

        .. parsed-literal::

            $ cilium install |CHART_VERSION| --set bgpControlPlane.enabled=true

IPv4/IPv6 single-stack and dual-stack setup are supported. Note that the BGP
Control Plane can only advertise the route of the address family that the
Cilium is configured to use. You cannot advertise IPv4 routes when the Cilium
Agent is configured to use only IPv6 address family. The opposite is also true.

Configure Peering
-----------------

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512

All BGP peering topology information is carried in a ``CiliumBGPPeeringPolicy``
CRD. A ``CiliumBGPPeeringPolicy`` can be applied to one or more nodes based on
its ``nodeSelector`` field. Only a single ``CiliumBGPPeeringPolicy`` can be
applied to a node. If multiple policies match a node, Cilium clears all BGP
sessions until only one policy matches the node.

.. warning::

   Applying another policy over an existing one will cause the BGP session to
   be cleared and causes immediate connectivity disruption. It is strongly
   recommended to test the policy in a staging environment before applying it
   to production.

Each ``CiliumBGPPeeringPolicy`` defines one or more ``virtualRouters``. The
virtual router defines a BGP router instance which is uniquely identified by
its ``localASN``. Each virtual router can have multiple ``neighbors`` defined.
The neighbor defines a BGP neighbor uniquely identified by its ``peerAddress``
and ``peerASN``. When ``localASN`` and ``peerASN`` are the same, iBGP peering
is used. When ``localASN`` and ``peerASN`` are different, eBGP peering is used.

Specifying Router ID (IPv6 single-stack only)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When Cilium is running on an IPv4 or a dual-stack, the BGP Router ID is
automatically derived from the IPv4 address assigned to the node. When Cilium
is running on an IPv6 single-stack cluster, the BGP Router ID must be
configured manually. This can be done by setting the annotation on the
Kubernetes Node resource:

.. code-block:: shell-session

   $ kubectl annotate node <node-name> cilium.io/bgp-virtual-router.64512="router-id=10.0.0.2"

Currently, you must set the annotation for each Node. In the future, automatic
assignment of the Router ID may be supported. Follow `#30333
<https://github.com/cilium/cilium/issues/30333/>`_ for updates.


Validating Peering Status
^^^^^^^^^^^^^^^^^^^^^^^^^

Once the ``CiliumBGPPeeringPolicy`` is applied, you can check the BGP peering
status with the Cilium CLI with the following command:

.. code-block:: shell-session

   $ cilium bgp peers
   Node                              Local AS   Peer AS   Peer Address     Session State   Uptime   Family         Received   Advertised
   node0                             64512      64512     10.0.0.1         established     10s      ipv4/unicast   0          0
                                                                                                    ipv6/unicast   0          0


Node Annotations
----------------

A ``CiliumBGPPeeringPolicy`` can apply to multiple nodes. When a
``CiliumBGPPeeringPolicy`` applies to one or more nodes each node will
instantiate one or more BGP routers as defined in ``virtualRouters``. However,
there are times when fine-grained control over an instantiated virtual router's
configuration needs to take place. This can be accomplished by applying a
Kubernetes annotation to Kubernetes Node resources.

A single annotation is used to specify a set of configuration attributes
to apply to a particular virtual router instantiated on a particular
host.

The syntax of the annotation is as follows:

::

       cilium.io/bgp-virtual-router.{asn}="key=value,..."

The ``{asn}`` portion should be replaced by the virtual router's local ASN you
wish to apply these configuration attributes to. Multiple option key/value
pairs can be specified by separating them with a comma. When duplicate keys are
defined with different values, the last key's value will be used.

Overriding Router ID
^^^^^^^^^^^^^^^^^^^^

When Cilium is running on an IPv4 single-stack or a dual-stack, the BGP Control
Plane can use the IPv4 address assigned to the node as the BGP Router ID
because Router ID is 32bit long, and we can rely on the uniqueness of the IPv4
address to make Router ID unique which is not the case for IPv6. Thus, when
running in an IPv6 single-stack, or when the auto assignment of the Router ID
is not desired, the administrator needs to manually define it. This can be
accomplished by setting the ``router-id`` key in the annotation.

.. code-block:: shell-session

   $ kubectl annotate node <node-name> cilium.io/bgp-virtual-router.{asn}="router-id=10.0.0.2"


Listening on the Local Port
^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, the BGP Control Plane instantiates each virtual router without a
listening port. This means the BGP router can only initiate connections to the
configured peers, but cannot accept incoming connections. This is the default
behavior because the BGP Control Plane is designed to function in environments
where another BGP router (such as ``Bird``) is running on the same node. When
it is required to accept incoming connections, the ``local-port`` key can be
used to specify the listening port.

.. code-block:: shell-session

   $ kubectl annotate node <node-name> cilium.io/bgp-virtual-router.{asn}="local-port=179"

Advertising PodCIDRs
--------------------

BGP Control Plane can advertise PodCIDR prefixes of the nodes selected by the
``CiliumBGPPeeringPolicy`` to the BGP peers. This allows the BGP peers to reach
the Pods directly without involving load balancers or NAT. There are two ways
to advertise PodCIDRs depending on the IPAM mode setting.

Kubernetes and ClusterPool IPAM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When :ref:`Kubernetes <k8s_hostscope>` or :ref:`ClusterPool
<ipam_crd_cluster_pool>` IPAM is used, set the
``virtualRouters[*].exportPodCIDR`` field to true.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       exportPodCIDR: true # <-- enable PodCIDR advertisement
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512

With this configuration, the BGP speaker on each node advertises the
PodCIDR prefixes assigned to the local node.

.. _bgp_control_plane_multipool_ipam:

MutliPool IPAM
^^^^^^^^^^^^^^

When :ref:`MultiPool IPAM <ipam_crd_multi_pool>` is used, specify the
``virtualRouters[*].podIPPoolSelector`` field. The ``.podIPPoolSelector`` field
is a label selector that selects allocated CIDRs of ``CiliumPodIPPool``
matching the specified ``.matchLabels`` or ``.matchExpressions``.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       podIPPoolSelector: # <-- select CiliumPodIPPool to advertise
         matchLabels:
           environment: production
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512

This advertises the PodCIDR prefixes allocated from the selected
CiliumPodIPPools. Note that the CIDR must be allocated to a ``CiliumNode`` that
matches the ``.nodeSelector`` for the virtual router to announce the PodCIDR as
a BGP route.

If you wish to announce ALL CiliumPodIPPool CIDRs within the cluster, a ``NotIn`` match expression
with a dummy key and value can be used like:

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       podIPPoolSelector:
         matchExpressions:
         - {key: somekey, operator: NotIn, values: ['never-used-value']}
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512

There are two special purpose selector fields that match CiliumPodIPPools based on ``name`` and/or
``namespace`` metadata instead of labels:

=============================== ===================
Selector                        Field
------------------------------- -------------------
io.cilium.podippool.namespace   ``.meta.namespace``
io.cilium.podippool.name        ``.meta.name``
=============================== ===================

For additional details regarding CiliumPodIPPools, see the :ref:`ipam_crd_multi_pool` section.

Other IPAM Types
^^^^^^^^^^^^^^^^

When using other IPAM types, the BGP Control Plane does not support advertising
PodCIDRs and specifying ``virtualRouters[*].exportPodCIDR`` doesn't take any
effect.

Advertising Service Virtual IPs
-------------------------------

In Kubernetes, a Service has multiple virtual IP addresses,
such as ``.spec.clusterIP``, ``.spec.clusterIPs``, ``.status.loadBalancer.ingress[*].ip``
and ``.spec.externalIPs``.
The BGP control plane can advertise the virtual IP address of the Service to BGP peers.
This allows users to directly access the Service from outside the cluster.

To advertise the virtual IPs, specify the ``virtualRouters[*].serviceSelector`` field
and the ``virtualRouters[*].serviceAdvertisements`` field. The ``.serviceAdvertisements``
defaults to the ``LoadBalancerIP`` service. You can also specify the ``.serviceAdvertisements``
field to advertise specific service types, with options such as ``LoadBalancerIP``,
``ClusterIP`` and ``ExternalIP``.

It is worth noting that when you configure ``virtualRouters[*].serviceAdvertisements`` as ``ClusterIP``,
the BGP Control Plane only considers the configuration of the service's ``.spec.internalTrafficPolicy`` and ignores
the configuration of ``.spec.externalTrafficPolicy``.
For ``ExternalIP`` and ``LoadBalancerIP``, it only considers the configuration of
the service's ``.spec.externalTrafficPolicy`` and ignores the configuration of ``.spec.internalTrafficPolicy``.

The ``.serviceSelector`` field is a label selector that selects Services matching
the specified ``.matchLabels`` or ``.matchExpressions``.

When your upstream router supports Equal Cost Multi Path(ECMP), you can use
this feature to load balance traffic to the Service across multiple nodes by
advertising the same ingress IPs from multiple nodes.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       serviceSelector: # <-- select Services to advertise
         matchLabels:
           app: foo
       serviceAdvertisements: # <-- specify the service types to advertise
       - LoadBalancerIP # <-- default
       - ClusterIP      # <-- options
       - ExternalIP     # <-- options
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512


Advertising ExternalIP Services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you wish to use this together with ``kubeProxyReplacement`` feature  (see :ref:`kubeproxy-free` docs),
please make sure the ExternalIP support is enabled.

If you only wish to advertise the ``.spec.externalIPs`` of Service,
you can specify the ``virtualRouters[*].serviceAdvertisements`` field as ``ExternalIP``.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       serviceSelector: # <-- select Services to advertise
         matchLabels:
           app: foo
       serviceAdvertisements: # <-- specify the service types to advertise
       - ExternalIP
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512


Advertising ClusterIP Services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you wish to use this together with ``kubeProxyReplacement`` feature  (see :ref:`kubeproxy-free` docs),
specific BPF parameters need to be enabled.
See :ref:`External Access To ClusterIP Services <external_access_to_clusterip_services>` section for how to enable it.

If you only wish to advertise the ``.spec.clusterIP`` and ``.spec.clusterIPs`` of Service,
you can specify the ``virtualRouters[*].serviceAdvertisements`` field as ``ClusterIP``.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       serviceSelector: # <-- select Services to advertise
         matchLabels:
           app: foo
       serviceAdvertisements: # <-- specify the service types to advertise
       - ClusterIP
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512

Additionally, when the ``.spec.clusterIP`` or ``.spec.clusterIPs`` of the Service contains ``None``,
this IP address will be ignored and will not be advertised.



Advertising Load Balancer Services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You must first allocate ingress IPs to advertise them. By default, Kubernetes
doesn't provide a way to assign ingress IPs to a Service. The cluster
administrator is responsible for preparing a controller that assigns ingress
IPs. Cilium supports assigning ingress IPs with the :ref:`Load Balancer IPAM
<lb_ipam>` feature.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       serviceSelector:
         matchLabels:
           app: foo
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512

This advertises the ingress IPs of all Services matching the ``.serviceSelector``.

If you wish to announce ALL services within the cluster, a ``NotIn`` match expression
with a dummy key and value can be used like:

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       serviceSelector:
          matchExpressions:
             - {key: somekey, operator: NotIn, values: ['never-used-value']}
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512

There are a few special purpose selector fields which don't match on labels but
instead on other metadata like ``.meta.name`` or ``.meta.namespace``.

=============================== ===================
Selector                        Field
------------------------------- -------------------
io.kubernetes.service.namespace ``.meta.namespace``
io.kubernetes.service.name      ``.meta.name``
=============================== ===================

Load Balancer Class
~~~~~~~~~~~~~~~~~~~

Cilium supports the `loadBalancerClass
<https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class>`__.
When the load balancer class is set to ``io.cilium/bgp-control-plane`` or unspecified,
Cilium will announce the ingress IPs of the Service. Otherwise, Cilium will not announce
the ingress IPs of the Service.

externalTrafficPolicy
~~~~~~~~~~~~~~~~~~~~~

When the Service has ``externalTrafficPolicy: Cluster``, BGP Control Plane
unconditionally advertises the ingress IPs of the selected Service. When the
Service has ``externalTrafficPolicy: Local``, BGP Control Plane keeps track of
the endpoints for the service on the local node and stops advertisement when
there's no local endpoint.

Validating Advertised Routes
----------------------------

Get all IPv4 unicast routes available:

.. code-block:: shell-session

   $ cilium bgp routes available ipv4 unicast
   Node                              VRouter   Prefix        NextHop   Age    Attrs
   node0                             64512     10.1.0.0/24   0.0.0.0   17m42s [{Origin: i} {Nexthop: 0.0.0.0}]

Get all IPv4 unicast routes available for a specific vrouter:

.. code-block:: shell-session

   $ cilium bgp routes available ipv4 unicast vrouter 64512
   Node                              VRouter   Prefix        NextHop   Age    Attrs
   node0                             64512     10.1.0.0/24   0.0.0.0   17m42s [{Origin: i} {Nexthop: 0.0.0.0}]

Get IPv4 unicast routes advertised to a specific peer:

.. code-block:: shell-session

   $ cilium bgp routes advertised ipv4 unicast peer 10.0.0.1
   Node                              VRouter   Prefix        NextHop   Age    Attrs
   node0                             64512     10.1.0.0/24   10.0.0.2  17m42s [{Origin: i} {AsPath: } {Nexthop: 10.0.0.2} {LocalPref: 100}]


Neighbor Options
----------------

Each ``virtualRouters`` can contain multiple ``neighbors``. You can specify
various BGP peering options for each neighbor. This section describes the
available options and use cases.

.. warning::

   Change of an existing neighbor configuration can cause reset of the existing BGP
   peering connection, which results in route flaps and transient packet loss while
   the session reestablishes and peers exchange their routes. To prevent packet loss,
   it is recommended to configure BGP Graceful Restart.

Peer Port
^^^^^^^^^

By default, the BGP Control Plane uses port 179 for BGP peering. When the neighbor is
running on a non-standard port, you can specify the port number with the ``peerPort``
field.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512
         peerPort: 1179 # <-- specify the peer port

Timers
^^^^^^

BGP Control Plane supports modifying the following BGP timer parameters. For
more detailed description for each timer parameters, please refer to `RFC4271
<https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class>`__.

================= ============================ ==========
Name              Field                        Default
----------------- ---------------------------- ----------
ConnectRetryTimer ``connectRetryTimeSeconds``  120
HoldTimer         ``holdTimeSeconds``          90
KeepaliveTimer    ``keepAliveTimeSeconds``     30
================= ============================ ==========

In datacenter networks which Kubernetes clusters are deployed, it is generally
recommended to set the ``HoldTimer`` and ``KeepaliveTimer`` to a lower value
for faster possible failure detection. For example, you can set the minimum
possible values ``holdTimeSeconds=9`` and ``keepAliveTimeSeconds=3``.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512
         connetRetryTimeSeconds: 90 # <-- specify the ConnectRetryTimer
         holdTimeSeconds: 9         # <-- specify the HoldTimer
         keepAliveTimeSeconds: 3    # <-- specify the KeepaliveTimer

eBGP Multihop
^^^^^^^^^^^^^

By default, IP TTL of the BGP packets is set to 1 in eBGP. Generally, it is
encouraged to not change the TTL, but in some cases, you may need to change the
TTL value. For example, when the BGP peer is a Route Server and located in a
different subnet, you may need to set the TTL value to more than 1.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512
         eBGPMultihopTTL: 4 # <-- specify the TTL value

MD5 Passwords
^^^^^^^^^^^^^

By configuring ``authSecretRef`` for a neighbor you can configure that a
`RFC-2385`_ TCP MD5 password should be configured on the session with this BGP
peer.

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512
         authSecretRef: "bgp-password" # <-- specify the secret name

``authSecretRef`` should reference the name of a secret in the BGP secrets
namespace (if using the Helm chart this is ``kube-system`` by default). The
secret should contain a key with a name of ``password``.

BGP secrets are limited to a configured namespace to keep the permissions
needed on each Cilium Agent instance to a minimum. The Helm chart will
configure Cilium to be able to read from it by default.

An example of creating a secret is:

.. code-block:: shell-session

   $ kubectl create secret generic -n kube-system --type=string secretname --from-literal=password=my-secret-password

If you wish to change the namespace, you can set the
``bgpControlPlane.secretNamespace.name`` Helm chart value. To have the
namespace created automatically, you can set the
``bgpControlPlane.secretNamespace.create`` Helm chart value  to ``true``.

Because TCP MD5 passwords sign the header of the packet they cannot be used if
the session will be address translated by Cilium (i.e. the Cilium Agent's pod
IP address must be the address the BGP peer sees).

If the password is incorrect, or the header is otherwise changed the TCP
connection will not succeed. This will appear as ``dial: i/o timeout`` in the
Cilium Agent's logs rather than a more specific error message.

.. _RFC-2385 : https://www.rfc-editor.org/rfc/rfc2385.html

If a ``CiliumBGPPeeringPolicy`` is deployed with an ``authSecretRef`` that Cilium cannot find, the BGP session will use an empty password and the agent will log an error such as in the following example::

   level=error msg="Failed to fetch secret \"secretname\": not found (will continue with empty password)" component=manager.fetchPeerPassword subsys=bgp-control-plane

.. _bgp_control_plane_graceful_restart:

Graceful Restart
^^^^^^^^^^^^^^^^
The Cilium BGP Control Plane can be configured to act as a graceful restart
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
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512
         gracefulRestart:
           enabled: true           # <-- enable graceful restart
           restartTimeSeconds: 120 # <-- set RestartTime

.. warning::

   When enabled, graceful restart capability is advertised for IPv4 and IPv6
   address families by default. From v1.15, we have a known issue where Cilium
   takes long time (approximately 300s) to restart route advertisement after
   graceful restart when Cilium advertises both IPv4 and IPv6 address families,
   but a remote peer advertises only one of them. You can work around this
   issue by aligning the address families advertised by Cilium and remote with
   the `families field <bgp-control-plane-address-families_>`_. You can track
   `#30367 <https://github.com/cilium/cilium/issues/30367/>`_ for updates.

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
^^^^^^^^^^^^^^^^^^^^^^^^^^

BGP advertisements can be extended with additional BGP Path Attributes - BGP Communities (`RFC-1997`_) or Local Preference.
These Path Attributes can be configured selectively for each BGP peer and advertisement type.

The following code block shows an example configuration of ``AdvertisedPathAttributes`` for a BGP neighbor,
which adds a BGP community attribute with the value ``64512:100`` to all Service announcements from the
matching ``CiliumLoadBalancerIPPool`` and sets the Local Preference value for all Pod CIDR announcements
to the value ``150``:

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512
         advertisedPathAttributes:
         - selectorType: CiliumLoadBalancerIPPool # <-- select CiliumLoadBalancerIPPool and add BGP community 64512:100
           selector:
             matchLabels:
               environment: production
           communities:
             standard:
             - 64512:100
         - selectorType: PodCIDR # <-- select PodCIDR and add local preference 150 and BGP community 64512:150
           localPreference: 150
           communities:
             standard:
             - 64512:150

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
The values can be of three types:

 - ``Standard``: represents a value of the "standard" 32-bit BGP Communities Attribute (`RFC-1997`_)
   as a 4-byte decimal number or two 2-byte decimal numbers separated by a colon (e.g. ``64512:100``).
 - ``WellKnown``: represents a value of the "standard" 32-bit BGP Communities Attribute (`RFC-1997`_)
   as a well-known string alias to its numeric value. Allowed values and their mapping to the numeric values:

    =============================== ================= =================
    Well-Known Value                Hexadecimal Value 16-bit Pair Value
    ------------------------------- ----------------- -----------------
    ``internet``                    ``0x00000000``    ``0:0``
    ``planned-shut``                ``0xffff0000``    ``65535:0``
    ``accept-own``                  ``0xffff0001``    ``65535:1``
    ``route-filter-translated-v4``  ``0xffff0002``    ``65535:2``
    ``route-filter-v4``             ``0xffff0003``    ``65535:3``
    ``route-filter-translated-v6``  ``0xffff0004``    ``65535:4``
    ``route-filter-v6``             ``0xffff0005``    ``65535:5``
    ``llgr-stale``                  ``0xffff0006``    ``65535:6``
    ``no-llgr``                     ``0xffff0007``    ``65535:7``
    ``blackhole``                   ``0xffff029a``    ``65535:666``
    ``no-export``                   ``0xffffff01``    ``65535:65281``
    ``no-advertise``                ``0xffffff02``    ``65535:65282``
    ``no-export-subconfed``         ``0xffffff03``    ``65535:65283``
    ``no-peer``                     ``0xffffff04``    ``65535:65284``
    =============================== ================= =================

 - ``Large``: represents a value of the BGP Large Communities Attribute (`RFC-8092`_),
   as three 4-byte decimal numbers separated by colons (e.g. ``64512:100:50``).

.. _RFC-1997 : https://www.rfc-editor.org/rfc/rfc1997.html
.. _RFC-8092 : https://www.rfc-editor.org/rfc/rfc8092.html

``LocalPreference`` defines the preference value advertised in the BGP Local Preference Path Attribute.
As Local Preference is only valid for ``iBGP`` peers, this value will be ignored for ``eBGP`` peers
(no Local Preference Path Attribute will be advertised).

Once configured, the additional Path Attributes advertised with the routes for a peer can be verified using the
``cilium bgp routes`` Cilium CLI command, for example:

.. code-block:: shell-session

   $ cilium bgp routes advertised ipv4 unicast peer 10.0.0.1

   VRouter   Prefix               NextHop     Age     Attrs
   64512     10.1.0.0/24          10.0.0.2    3m31s   [{Origin: i} {LocalPref: 150} {Nexthop: 10.0.0.2}]
   64512     192.168.100.190/32   10.0.0.2    3m32s   [{Origin: i} {LocalPref: 100} {Communities: 64512:100} {Nexthop: 10.0.0.2}]

.. _bgp-control-plane-address-families:

Address Families
^^^^^^^^^^^^^^^^

By default, the BGP Control Plane advertises IPv4 Unicast and IPv6 Unicast
Multiprotocol Extensions Capability (`RFC-4760`_) as well as Graceful Restart
address families (`RFC-4724`_) if enabled. If you wish to change the default
behavior and advertise only specific address families, you can use the
``families`` field. The ``families`` field is a list of AFI (Address Family
Identifier) and SAFI (Subsequent Address Family Identifier) pairs. The only
options currently supported are ``{afi: ipv4, safi: unicast}`` and ``{afi:
ipv6, safi: unicast}``.

Following example shows how to advertise only IPv4 Unicast address family:

.. _RFC-4760 : https://www.rfc-editor.org/rfc/rfc4760.html

.. code-block:: yaml

   apiVersion: "cilium.io/v2alpha1"
   kind: CiliumBGPPeeringPolicy
   metadata:
     name: rack0
   spec:
     nodeSelector:
       matchLabels:
         rack: rack0
     virtualRouters:
     - localASN: 64512
       neighbors:
       - peerAddress: '10.0.0.1/32'
         peerASN: 64512
         families:
         - afi: ipv4
           safi: unicast
