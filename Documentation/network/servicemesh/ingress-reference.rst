Reference
#########

How Cilium Ingress and Gateway API differ from other Ingress controllers
************************************************************************

One of the biggest differences between Cilium's Ingress and Gateway API support
and other Ingress controllers is how closely tied the implementation is to the
CNI. For Cilium, Ingress and Gateway API are part of the networking stack,
and so behave in a different way to other Ingress or Gateway API controllers
(even other Ingress or Gateway API controllers running in a Cilium cluster).

Other Ingress or Gateway API controllers are generally installed as a Deployment
or Daemonset in the cluster, and exposed via a Loadbalancer Service or similar (which Cilium
can, of course, enable).

Cilium's Ingress and Gateway API config is exposed with a Loadbalancer or NodePort
service, or optionally can be exposed on the Host network also. But in all of
these cases, when traffic arrives at the Service's port, eBPF code intercepts
the traffic and transparently forwards it to Envoy (using the TPROXY kernel facility).

This affects things like client IP visibility, which works differently for Cilium's
Ingress and Gateway API support to other Ingress controllers.

It also allows Cilium's Network Policy engine to apply CiliumNetworkPolicy to
traffic bound for and traffic coming from an Ingress.

Cilium's ingress config and CiliumNetworkPolicy
***********************************************

Ingress and Gateway API traffic bound to backend services via Cilium passes through a
per-node Envoy proxy.

The per-node Envoy proxy has special code that allows it to interact with the
eBPF policy engine, and do policy lookups on traffic. This allows Envoy to be
a Network Policy enforcement point, both for Ingress (and Gateway API) traffic,
and also for east-west traffic via GAMMA or L7 Traffic Management.

However, for ingress config, there's also an additional step. Traffic that arrives at
Envoy *for Ingress or Gateway API* is assigned the special ``ingress`` identity
in Cilium's Policy engine.

Traffic coming from outside the cluster is usually assigned the ``world`` identity
(unless there are IP CIDR policies in the cluster). This means that there are
actually *two* logical Policy enforcement points in Cilium Ingress - before traffic
arrives at the ``ingress`` identity, and after, when it is about to exit the
per-node Envoy.

.. image:: /images/ingress-policy.png
    :align: center

This means that, when applying Network Policy to a cluster, it's important to
ensure that both steps are allowed, and that traffic is allowed from ``world`` to
``ingress``, and from ``ingress`` to identities in the cluster (like the
``productpage`` identity in the image above).

Please see the :ref:`gs_ingress_and_network_policy` for more details for Ingress,
although the same principles also apply for Gateway API.

Source IP Visibility
********************

.. Note::

    By default, source IP visibility for Cilium ingress config, both Ingress
    and Gateway API, should *just work* on most installations. Read this section
    for more information on requirements and relevant settings.

Having a backend be able to deduce what IP address the actual request came from
is important for most applications.

By default, Cilium's Envoy instances are configured to append the visible source
address of incoming HTTP connections to the ``X-Forwarded-For`` header, using the
usual rules. That is, by default Cilium sets the number of trusted hops to ``0``,
indicating that Envoy should use the address the connection is opened from, rather
than a value inside the ``X-Forwarded-For`` list. Increasing this count will
have Envoy use the ``n`` th value from the list, counting from the right.

Envoy will also set the ``X-Envoy-External-Address`` header to the trusted client
address, whatever that turns out to be, based on ``X-Forwarded-For``.

.. Note::
    
    Backends using Cilium ingress (whether via Ingress or Gateway API) should
    just see the ``X-Forwarded-For`` and ``X-Envoy-External-Address`` headers (which
    are handled transparently by many HTTP libraries).

``externalTrafficPolicy`` for Loadbalancer or NodePort Services
===============================================================

Cilium's ingress support (both for Ingress and Gateway API) often uses a Loadbalancer
or NodePort Service to expose the Envoy Daemonset.

In these cases, the Service object has one field that is particularly relevant
to Client IP visibility - the ``externalTrafficPolicy`` field.

It has two relevant settings:

- ``Local``: Nodes will only route traffic to Pods running on the local node, 
  *without masquerading the source IP*. Because of this, in clusters that use
  ``kube-proxy``, this is the only way to ensure source IP visibility. Part of
  the contract for ``externalTrafficPolicy`` local is also that the node will
  open a port (the ``healthCheckNodePort``, automatically set by Kubernetes when
  ``externalTrafficPolicy: Local`` is set), and requests to
  ``http://<nodeIP>:<healthCheckNodePort>/healthz`` will return 200 on nodes that
  have local pods running, and non-200 on nodes that don't. Cilium implements this
  for general Loadbalancer Services, but it's a bit different for Cilium ingress
  config (both Ingress and Gateway API).
- ``Cluster``: Node will route to all endpoints across the cluster evenly. This
  has a couple of other effects: Firstly, upstream loadbalancers will expect to
  be able to send traffic to any node and have it end up at a backend Pod, and
  the node *may* masquerade the source IP. This means that in many cases,
  ``externalTrafficPolicy: Cluster`` may mean that the backend pod does *not* see
  the source IP.

In Cilium's case, all ingress traffic bound for a Service that exposes Envoy is
*always* going to the local node, and is *always* forwarded to Envoy using the
Linux Kernel TPROXY function, which transparently forwards packets to the backend.

This means that for Cilium ingress config, for both Ingress and Gateway API, things
work a little differently in both ``externalTrafficPolicy`` cases.

.. Note::

    In *both* ``externalTrafficPolicy`` cases, traffic will arrive at any node
    in the cluster, and be forwarded to *Envoy* **while keeping the source IP intact**.

Also, for any Services that exposes Cilium's Envoy, Cilium will ensure that
when ``externalTrafficPolicy: Local`` is set, every node in the cluster will
pass the ``healthCheckNodePort`` check, so that external load balancers will
forward correctly.

However, for Cilium's ingress config, both Ingress and Gateway API, **it is not
necessary** to configure ``externalTrafficPolicy: Local`` to keep the source IP
visible to the backend pod (via the ``X-Forwarded-For`` and ``X-Envoy-External-Address``
fields).

TLS Passthrough and source IP visibility
========================================

Both Ingress and Gateway API support TLS Passthrough configuration (via annotation
for Ingress, and the TLSRoute resource for Gateway API). This configuration allows
multiple TLS Passthrough backends to share the same TLS port on a loadbalancer,
with Envoy inspecting the Server Name Indicator (SNI) field of the TLS handshake,
and using that to forward the TLS stream to a backend.

However, this poses problems for source IP visibility, because Envoy is doing a
TCP Proxy of the TLS stream.

What happens is that the TLS traffic arrives at Envoy, terminating a TCP stream,
Envoy inspects the client hello to find the SNI, picks a backend to forward to,
then starts a new TCP stream and forwards the TLS traffic inside the downstream
(outside)  packets to the upstream (the backend).

Because it's a new TCP stream, as far as the backends are concerned, the source
IP is Envoy (which is often the Node IP, depending on your Cilium config).

.. Note::

    When doing TLS Passthrough, backends will see Cilium Envoy's IP address
    as the source of the forwarded TLS streams.
