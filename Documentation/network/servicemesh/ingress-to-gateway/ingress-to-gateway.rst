.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress-to-gateway:

*********************************
Migrating from Ingress to Gateway
*********************************

The Gateway API is not only the long-term successor to the Ingress API, it also supports use cases beyond HTTP/HTTPS-based applications.

This section highlights some of the limitations with Ingress, explains some of the benefits of the Gateway API, and describes 
some of the options available with migrating from Ingress API to Gateway API.

Ingress API Limitations
#######################

Development of the Gateway API stemmed from the realization that the Kubernetes Ingress API has some limitations.

- Limited support for advanced routing
  
The Ingress API supports basic routing based on path and host rules, but it lacks native support for more advanced routing 
features such as traffic splitting, header modification, and URL rewriting.

- Limited protocol support
  
The Ingress API only supports HTTP and HTTPS traffic, and does not natively support other protocols like TCP or UDP.
The Ingress API specification was too limited and not extensible enough. To address these technical limitations, 
software vendors and developers created vendor-specific annotations. However, using annotations 
created inconsistencies from one Ingress Controller to another. For example, issues often arise when switching from one Ingress Controller to another because annotations are often vendor-specific.

- Operational constraints
  
Finally, the Ingress API suffers from operational constraints: it is not well suited for multi-team clusters with shared load-balancing infrastructure.

Benefits of the Gateway API
###########################

The Gateway API was designed to address the limitations of Ingress API. The `Kubernetes SIG-Network <https://github.com/kubernetes/community/tree/master/sig-network>`_ team designs and maintains the Gateway API.

For more information about the Gateway API, see `the Gateway API project page <https://gateway-api.sigs.k8s.io/>`_.

The Gateway API provides a centralized mechanism for managing and enforcing policies for external traffic, 
including HTTP routing, TLS termination, traffic splitting/weighting, and header modification.

Native support of policies for external traffic means that annotations are no longer required to support ingress traffic patterns. This means that Gateway API resources are more portable from one Gateway API implementation to another.

When customization is required, Gateway API provides several flexible models, including specific extension points to enable diverse 
traffic patterns. As the Gateway API team adds extensions, the team looks for common denominators and promotes features of API conformance to maximize the ease of extending Ingress API resources.

Finally, the Gateway API is designed with role-based personas in mind. The Ingress model is based on a persona where 
developers manage and create ingress and service resources themselves.

In more complex deployments, more personas are involved:

- Infrastructure Providers administrate the managed services of a cloud provider, or the infrastructure/network team when running Kubernetes on-premises.
- Cluster Operators are responsible for the administration of a cluster.
- Application Developers are responsible for defining application configuration and service composition.

By deconstructing the Ingress API into several Gateway API objects, personas gain the specific access and privileges that their responsibilities require.

For example, application developers in a specific team could be assigned permissions to create Route objects in a specified namespace 
without also gaining permissions to modify the Gateway configuration or edit Route objects in namespaces other than theirs.

Migration Methods
#################

There are two primary methods to migrate Ingress API resources to Gateway API:

- *manual*: manually creating Gateway API resources based on existing Ingress API resources.
- *automated*: creating rules using the `ingress2gateway tool <https://github.com/kubernetes-sigs/ingress2gateway>`_. 
  The ingress2gateway project reads Ingress resources from a Kubernetes cluster based on your current Kube Config. It outputs YAML for equivalent Gateway API resources to stdout.

.. note::
  
    The ``ingress2gateway`` tool remains experimental and is not recommended for production.

Ingress Annotations Migration
#############################

Most Ingress controllers use annotations to provide support for specific features, such as HTTP request manipulation and routing. 
As noted in `Benefits of the Gateway API`_, the Gateway API avoids implementation-specific annotations in order to provide a portable configuration.

As a consequence, it's rare to port implementation-specific Ingress annotations to a Gateway API resource. 
Instead, the Gateway API provides native support for some of these features, including:

- Request/response manipulation
- Traffic splitting
- Header, query parameter, or method-based routing

Examples
########

For examples of migrating to Cilium's Gateway API features, see:

.. toctree::
   :maxdepth: 1
   :glob:

   http-migration
   tls-migration

