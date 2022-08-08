.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

*******************
Security Identities
*******************

Security identities are generated from labels. They are stored as ``uint32``,
which means the maximum limit for a security identity is ``2^32 - 1``. The
minimum security identity is ``1``.

.. note::

   Identity 0 is not a valid value. If it shows up in Hubble output, this means
   the identity was not found. In the eBPF datapath, it has a special role
   where it denotes "any identity", i.e. as a wildcard allow in policy maps.

Security identities span over several ranges, depending on the context:

1) Cluster-local
2) ClusterMesh
3) Identities generated from CIDR-based policies

Cluster-local identities (1) range from ``1`` to ``2^16 - 1``. The lowest
values, from ``1`` to ``255``, correspond to the reserved identity range.  See
the `internal code documentation
<https://pkg.go.dev/github.com/cilium/cilium/pkg/identity#NumericIdentity>`__
for details.

For ClusterMesh (2), 8 bits are used as the ``cluster-id`` which identifies the
cluster in the ClusterMesh, into the 3rd octet as shown by ``0x00FF0000``. The
4th octet (uppermost bits) must be set to ``0`` as well. Neither of these
constraints apply CIDR identities however, see (3).

CIDR identities (3) are local to each node. CIDR identities begin from ``1``
and end at ``16777215``, however since they're shifted by ``24``, this makes
their effective range ``1 | (1 << 24)`` to ``16777215 | (1 << 24)`` or from
``16777217`` to ``33554431``. When CIDR policies are applied, the identity
generated is local to each node. In other words, the identity may not be the
same for the same CIDR policy across two nodes.

CIDR identities are never used for traffic between Cilium-managed nodes, so
they do not need to fit inside of a VXLAN or Geneve virtual network field.
Non-CIDR identities are limited to 24 bits so that they will fit in these
fields on the wire, but since CIDR identities will not be encoded in these
packets, they can start with a higher value. Hence, the minimum value for a
CIDR identity is ``2^24 + 1``.

Overall, the following represents the different ranges:

::

   0x00000001 - 0x000000FF (1           to 2^8  - 1)        => reserved identities
   0x00000100 - 0x0000FFFF (2^8         to 2^16 - 1)        => cluster-local identities
   0x00010000 - 0x00FFFFFF (2^16        to 2^24 - 1)        => identities for remote clusters
   0x01000000 - 0x0100FFFF (2^24        to 2^24 + 2^16 - 1) => identities for CIDRs (node-local)
   0x01010000 - 0xFFFFFFFF (2^24 + 2^16 to 2^32 - 1)        => reserved for future use
