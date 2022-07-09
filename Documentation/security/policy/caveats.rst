.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _policy_caveats:

*******
Caveats
*******

Security Identity for N/S Service Traffic
=========================================

When accessing a Kubernetes service from outside the cluster, the
:ref:`arch_id_security` assignment depends on the routing mode.

In the tunneling mode (i.e., ``--tunnel-protocol=vxlan`` or ``--tunnel-protocol=geneve``), the request
to the service will have the ``reserved:world`` security identity.

In the native-routing mode (i.e., ``--routing-mode=native``), the security identity
will be set to the ``reserved:world`` if the request was sent to the node which runs the
selected endpoint by the LB. If not, i.e., the request needs to be forwarded to
another node after the service endpoint selection, then it will have the ``reserved:remote-node``.

The latter traffic will match ``fromEntities: cluster`` policies.

Differences From Kubernetes Network Policies
============================================

When creating Cilium Network Policies it is important to keep in mind that Cilium Network
Policies do not perfectly replicate the functionality of `Kubernetes Network Policies <https://kubernetes.io/docs/concepts/services-networking/network-policies/>`_.
See :ref:`this table <networkpolicy_state>` for differences.
