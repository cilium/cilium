.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _servicemesh_root:

************
Service Mesh
************

What is Service Mesh?
#####################

With the introduction of distributed applications, additional visibility,
connectivity, and security requirements have surfaced. Application components
communicate over untrusted networks across cloud and premises boundaries,
load-balancing is required to understand application protocols, resiliency is
becoming crucial, and security must evolve to a model where sender and receiver
can authenticate each other’s identity. In the early days of distributed
applications, these requirements were resolved by directly embedding the
required logic into the applications. A service mesh extracts these features out
of the application and offers them as part of the infrastructure for all
applications to use and thus no longer requires to change each application.

Looking at the feature set of a service mesh today, it can be summarized as follows:

- **Resilient Connectivity**: Service to service communication must be possible across
  boundaries such as clouds, clusters, and premises. Communication must be
  resilient and fault tolerant.
- **L7 Traffic Management**: Load balancing, rate limiting, and resiliency must be
  L7-aware (HTTP, REST, gRPC, WebSocket, …).
- **Identity-based Security**: Relying on network identifiers to achieve security is
  no longer sufficient, both the sending and receiving services must be able to
  authenticate each other based on identities instead of a network identifier.
- **Observability & Tracing**: Observability in the form of tracing and metrics is
  critical to understanding, monitoring, and troubleshooting application stability,
  performance, and availability.
- **Transparency**: The functionality must be available to applications in a
  transparent manner, i.e. without requiring to change application code.

.. admonition:: Video
  :class: attention

  If you'd like a video explanation of Cilium's Service Mesh implementation, check out `eCHO episode 27: eBPF-enabled Service Mesh <https://www.youtube.com/watch?v=nJT0ASbGLvs>`__ and `eCHO episode 100: Next-gen mutual authentication in Cilium <https://www.youtube.com/watch?v=BWjDlynXhzg>`__.

Why Cilium Service Mesh?
########################

Since its early days, Cilium has been well aligned with the service mesh concept
by operating at both the networking and the application protocol layer to provide
connectivity, load-balancing, security, and observability. For all network
processing including protocols such as IP, TCP, and UDP, Cilium uses eBPF as the
highly efficient in-kernel datapath. Protocols at the application layer such as
HTTP, Kafka, gRPC, and DNS are parsed using a proxy such as Envoy. 

.. toctree::
   :maxdepth: 3
   :glob:

   ingress
   gateway-api/gateway-api
   gateway-api/gamma
   ingress-to-gateway/ingress-to-gateway
   istio
   mutual-authentication/mutual-authentication
   l7-traffic-management
