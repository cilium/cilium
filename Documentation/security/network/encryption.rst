.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gsg_encryption:

************************************
Transparent Encryption
************************************

Cilium supports the transparent encryption of Cilium-managed host traffic and
traffic between Cilium-managed endpoints either using IPsec or WireGuard®:

.. toctree::
   :maxdepth: 1
   :glob:

   encryption-ipsec
   encryption-wireguard


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

The workaround for this issue is to ensure that the endpoint is not allowed to
send unencrypted traffic to arbitrary targets outside of the cluster. This can
be achieved by defining an egress policy which either completely disallows
traffic to ``reserved:world`` identities, or only allows egress traffic
to addresses outside of the cluster to a certain subset of trusted IP
addresses using ``toCIDR``, ``toCIDRSet`` and ``toFQDN`` rules.
See :ref:`policy_examples` for more details about how to write network
policies that restrict egress traffic to certain endpoints.
