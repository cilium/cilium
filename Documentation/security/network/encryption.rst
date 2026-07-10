.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gsg_encryption:

************************************
Transparent Encryption
************************************

Cilium supports the transparent encryption of Cilium-managed host traffic and
traffic between Cilium-managed endpoints using IPsec, WireGuard®, or ztunnel:

.. toctree::
   :maxdepth: 1
   :glob:

   encryption-ipsec
   encryption-wireguard
   encryption-ztunnel

.. admonition:: Video
 :class: attention

  You can also see a demo of Cilium Transparent Encryption in `eCHO episode 79: Transparent Encryption with IPsec and WireGuard <https://www.youtube.com/watch?v=vj7M-t9MK6s>`__.

Known Issues and Workarounds
============================

Egress traffic to not yet discovered remote endpoints may be unencrypted
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To determine if a packet needs to be encrypted or not, transparent encryption
relies on the same mechanisms as policy enforcement to decide if the destination
of an outgoing packet belongs to a Cilium-managed endpoint on a remote node.
This means that if an endpoint is allowed to initiate traffic to targets outside
of the cluster, it is possible for that endpoint to send packets to arbitrary
IP addresses before Cilium learns that a particular IP address belongs to a
remote Cilium-managed endpoint or newly joined remote Cilium host in the cluster.
In such a case there is a time window during which Cilium will send out the
initial packets unencrypted, as it has to assume the destination IP address is
outside of the cluster. Once the information about the newly created endpoint
has propagated in the cluster and Cilium knows that the IP address is an
endpoint on a remote node, it will start encrypting packets using the encryption
key of the remote node.

One workaround for this issue is to ensure that the endpoint is not allowed to
send unencrypted traffic to arbitrary targets outside of the cluster. This can
be achieved by defining an egress policy which either completely disallows
traffic to ``reserved:world`` identities, or only allows egress traffic
to addresses outside of the cluster to a certain subset of trusted IP
addresses using ``toCIDR``, ``toCIDRSet`` and ``toFQDN`` rules.
See the :ref:`chapter on network policies <network_policy>` for more details
about how to write network policies that restrict egress traffic to certain
endpoints.

Another way to mitigate this issue is to set
``encryption.strictMode.egress.enabled`` to ``true`` and the expected pod
CIDR as ``encryption.strictMode.egress.cidr``. This encryption strict mode
egress enforces that traffic exiting a node to the set CIDR is always
encrypted. Be aware that information about new pod endpoints must
propagate to the node before the node can send traffic to them.

Encryption strict mode egress has the following limitations:

- The pod CIDR and therefore the encryption strict mode egress CIDR must be
  IPv4. IPv6 traffic is not protected by the strict mode and can be leaked.
- To disable all dynamic lookups, you must use direct routing mode and the
  node CIDR and pod CIDR must not overlap. Otherwise,
  ``encryption.strictMode.egress.allowRemoteNodeIdentities`` must be set to
  ``true``. This allows unencrypted traffic sent from or to an IP address
  associated with a node identity.

Encryption strict mode ingress can be enabled via
``encryption.strictMode.ingress.enabled``. When enabled, any cluster-internal
ingress traffic that did not arrive on the node through the WireGuard tunnel
is dropped, preventing unencrypted pod traffic from reaching local endpoints.
Strict mode ingress is supported with both tunnel and native routing modes,
and requires WireGuard encryption (it is not supported with IPsec).

Encryption strict mode ingress has the following limitations:

- Node-to-node encryption for wireguard is not protected by strict mode 
  ingress. Enforcement only applies to cluster-internal pod traffic destined
  for local endpoints.
- Enforcement relies on Cilium's BPF programs being attached to all
  pod-routable network interfaces. If the node has additional interfaces that
  Cilium does not manage (and therefore has no BPF program attached to), an
  attacker could inject unencrypted pod traffic through those interfaces,
  bypassing strict mode ingress. Ensure that all interfaces capable of
  carrying pod traffic are managed by Cilium.
- It is currently not supported when chaining Cilium on top of other CNI
  plugins. For more information, see GitHub issue 15596.
