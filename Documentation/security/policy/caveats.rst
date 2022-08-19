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

In the tunneling mode (i.e., ``--tunnel=vxlan`` or ``--tunnel=geneve``), the request
to the service will have the ``reserved:world`` security identity.

In the direct-routing mode (i.e., ``--tunnel=disabled``), the security identity
will be set to the ``reserved:world`` if the request was sent to the node which runs the
selected endpoint by the LB. If not, i.e., the request needs to be forwarded to
another node after the service endpoint selection, then it will have the ``reserved:remote-node``.

The latter traffic will match ``fromEntities: cluster`` policies.

Differences From Kubernetes Network Policies
============================================

When creating Cilium Network Policies it is important to keep in mind that Cilium Network
Policies do not perfectly replicate the functionality of `Kubernetes Network Policies <https://kubernetes.io/docs/concepts/services-networking/network-policies/>`_.

There are two ways Cilium Network Policies do not overlap with existing Kubernetes Network
Policy functionality:

1. Cilium Network Policies that reference the Stream Control Transmission Protocol (SCTP)
   will not work properly. Currently, Cilium does not support SCTP (see :gh-issue:`5719`).

2. Cilium Network Policies that use CIDR blocks to define endpoints controlled by Cilium
   (i.e. internal to the Kubernetes cluster) will not work properly. As stated under the
   :ref:`policy_cidr` section of this documentation, CIDR policies in Cilium are used to
   define policies to and from endpoints which are not managed by Cilium (i.e. external
   to the Kubernetes cluster). This differs from Kubernetes Network Policies which **can**
   use CIDR blocks to define policies to and from endpoints which are internal to the
   Kubernetes cluster (i.e. managed by a CNI other than Cilium).
