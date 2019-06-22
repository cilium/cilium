.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _concepts_security:

********
Security
********

Cilium provides security on multiple levels. Each can be used individually or
combined together.

* :ref:`arch_id_security`: Connectivity policies between endpoints (Layer 3),
  e.g. any endpoint with label ``role=frontend`` can connect to any endpoint with
  label ``role=backend``.
* Restriction of accessible ports (Layer 4) for both incoming and outgoing
  connections, e.g. endpoint with label ``role=frontend`` can only make outgoing
  connections on port 443 (https) and endpoint ``role=backend`` can only accept
  connections on port 443 (https).
* Fine grained access control on application protocol level to secure HTTP and
  remote procedure call (RPC) protocols, e.g the endpoint with label
  ``role=frontend`` can only perform the REST API call ``GET /userdata/[0-9]+``,
  all other API interactions with ``role=backend`` are restricted.

Currently on the roadmap, to be added soon:

* Authentication: Any endpoint which wants to initiate a connection to an
  endpoint with the label ``role=backend`` must have a particular security
  certificate to authenticate itself before being able to initiate any
  connections. See `GH issue 502
  <https://github.com/cilium/cilium/issues/502>`_ for additional details.
* Encryption: Communication between any endpoint with the label ``role=frontend``
  to any endpoint with the label ``role=backend`` is automatically encrypted with
  a key that is automatically rotated. See `GH issue 504
  <https://github.com/cilium/cilium/issues/504>`_ to track progress on this
  feature.

.. _arch_id_security:

Identity based Connectivity Access Control
==========================================

Container management systems such as Kubernetes deploy a networking model which
assigns an individual IP address to each pod (group of containers). This
ensures simplicity in architecture, avoids unnecessary network address
translation (NAT) and provides each individual container with a full range of
port numbers to use. The logical consequence of this model is that depending on
the size of the cluster and total number of pods, the networking layer has to
manage a large number of IP addresses.

Traditionally security enforcement architectures have been based on IP address
filters.  Let's walk through a simple example: If all pods with the label
``role=frontend`` should be allowed to initiate connections to all pods with
the label ``role=backend`` then each cluster node which runs at least one pod
with the label ``role=backend`` must have a corresponding filter installed
which allows all IP addresses of all ``role=frontend`` pods to initiate a
connection to the IP addresses of all local ``role=backend`` pods. All other
connection requests should be denied. This could look like this: If the
destination address is *10.1.1.2* then allow the connection only if the source
address is one of the following *[10.1.2.2,10.1.2.3,20.4.9.1]*.

Every time a new pod with the label ``role=frontend`` or ``role=backend`` is
either started or stopped, the rules on every cluster node which run any such
pods must be updated by either adding or removing the corresponding IP address
from the list of allowed IP addresses. In large distributed applications, this
could imply updating thousands of cluster nodes multiple times per second
depending on the churn rate of deployed pods. Worse, the starting of new
``role=frontend`` pods must be delayed until all servers running
``role=backend`` pods have been updated with the new security rules as
otherwise connection attempts from the new pod could be mistakenly dropped.
This makes it difficult to scale efficiently.

In order to avoid these complications which can limit scalability and
flexibility, Cilium entirely separates security from network addressing.
Instead, security is based on the identity of a pod, which is derived through
labels.  This identity can be shared between pods. This means that when the
first ``role=frontend`` pod is started, Cilium assigns an identity to that pod
which is then allowed to initiate connections to the identity of the
``role=backend`` pod. The subsequent start of additional ``role=frontend`` pods
only requires to resolve this identity via a key-value store, no action has to
be performed on any of the cluster nodes hosting ``role=backend`` pods. The
starting of a new pod must only be delayed until the identity of the pod has
been resolved which is a much simpler operation than updating the security
rules on all other cluster nodes.

.. image:: ../images/identity.png
    :align: center


Policy Enforcement
==================

All security policies are described assuming stateful policy enforcement for
session based protocols. This means that the intent of the policy is to
describe allowed direction of connection establishment. If the policy allows
``A => B`` then reply packets from ``B`` to ``A`` are automatically allowed as
well.  However, ``B`` is not automatically allowed to initiate connections to
``A``. If that outcome is desired, then both directions must be explicitly
allowed.

Security policies may be enforced at *ingress* or *egress*. For *ingress*,
this means that each cluster node verifies all incoming packets and determines
whether the packet is allowed to be transmitted to the intended endpoint.
Correspondingly, for *egress* each cluster node verifies outgoing packets and
determines whether the packet is allowed to be transmitted to its intended
destination.

In order to enforce identity based security in a multi host cluster, the
identity of the transmitting endpoint is embedded into every network packet
that is transmitted in between cluster nodes. The receiving cluster node can
then extract the identity and verify whether a particular identity is allowed
to communicate with any of the local endpoints.

Default Security Policy
-----------------------

If no policy is loaded, the default behavior is to allow all communication
unless policy enforcement has been explicitly enabled. As soon as the first
policy rule is loaded, policy enforcement is enabled automatically and any
communication must then be white listed or the relevant packets will be
dropped.

Similarly, if an endpoint is not subject to an *L4* policy, communication from
and to all ports is permitted. Associating at least one *L4* policy to an
endpoint will block all connectivity to ports unless explicitly allowed.


Orchestration System Specifics
==============================

Kubernetes
----------

Cilium regards each deployed `Pod` as an endpoint with regards to networking and
security policy enforcement. Labels associated with pods can be used to define
the identity of the endpoint.

When two pods communicate via a service construct, then the labels of the
origin pod apply to determine the identity.
