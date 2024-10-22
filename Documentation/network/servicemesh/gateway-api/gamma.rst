.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gamma:

*******************
GAMMA Support
*******************

What is GAMMA?
####################

(From the `GAMMA page <https://gateway-api.sigs.k8s.io/mesh/gamma/>`__
on the Gateway API site):

The GAMMA initiative is a dedicated workstream within the Gateway API
subproject, shepherded by the GAMMA leads, rather than being a separate
subproject. GAMMA’s goal is to define how Gateway API can be used to configure
a service mesh, with the intention of making minimal changes to Gateway API and
always preserving the role-oriented nature of Gateway API. Additionally, GAMMA
strives to advocate for consistency between implementations of Gateway API by
service mesh projects, regardless of their technology stack or proxy.

In Gateway API v1.0, GAMMA supports adding extra HTTP routing to Services by
binding a HTTPRoute to a Service as a parent (as opposed to the north/south
Gateway API usage of binding a HTTPRoute to a Gateway as a parent).

This allows Cilium to intercept layer 7 traffic flowing to a parent Service and
route the traffic through the per-node Envoy proxy. Because of this, GAMMA
performs the same function as Cilium's
:ref:`Layer 7 traffic management <gs_l7_traffic_management>`, without the user
needing to know anything about configuring Envoy directly.

Types of GAMMA configuration
############################

In GAMMA, there are two types of HTTPRoutes: "producer" and "consumer" Routes.

"Producer" routes are HTTPRoutes that bind to a Service that lives in the same
namespace and have the same owner as the owner of the Service whose traffic is
being managed. So, for an application ``foo``, in the namespace ``foo``, with a
Service called ``foo-svc``, the owner of ``foo`` would create a HTTPRoute in the ``foo``
namespace that lists ``foo-svc`` as its parent. The routing then affects all traffic
coming to the ``foo`` service from the whole cluster, and is controlled by the
"producer" of the ``foo`` service - its owner.

"Consumer" routes are HTTPRoutes that bind to a Service that lives in a different
namespace than that Service. These Routes are called "consumer" Routes because
they are owned by the _consumer_ of the Service they bind to. For the ``foo`` Service
above, a Route in the ``bar`` namespace, to be used by the app in that namespace,
that binds to the ``foo-svc`` Service in the ``foo`` namespace is a _consumer_ Service
because it changes the routing for the ``bar`` service, which _consumes_ the ``foo``
Service.

Cilium currently supports only "Producer" Routes, and so HTTPRoutes must be
in the same namespace as the Service that they are binding to.

Cilium GAMMA Support
##########################

Cilium supports GAMMA v1.0.0 for the following resources:  

- `HTTPRoute <https://gateway-api.sigs.k8s.io/api-types/httproute/>`_  
- `ReferenceGrant <https://gateway-api.sigs.k8s.io/api-types/referencegrant/>`_  

Cilium support is limited to passing the Core conformance  
tests and two out of three Extended Mesh tests. Note that GAMMA is itself  
experimental as at Gateway API v1.0.0.  

Cilium currently does not support "consumer" HTTPRoutes, and so does not  
support the ``MeshConsumerRoute`` feature of the Mesh conformance profile.  

.. include:: installation.rst
