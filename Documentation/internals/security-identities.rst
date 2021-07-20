.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _security_identities:

*******************
Security Identities
*******************

Security identities are generated from labels. They are stored as ``uint16``,
which means the maximum limit for a security identity is ``2^16 - 1``. The
minimum security identity is ``256``, because reserve the identities from ``1``
to ``255``.

There are two caveats to the above however:

1) ClusterMesh
2) Identities generated from CIDR-based policies

1) TODO: Explain ClusterMesh
2) CIDR identities are local to each node. This means that they're not subject
   to the global limit of security identities (``2^16 - 1``). CIDR identities
   begin from ``1`` and end at ``16777215``, however since they're shifted by
   ``24``, this makes their effective range ``1 | (1 << 24)`` to ``16777215 |
   (1 << 24)``.
