.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress-to-gateway:

*********************************
Migrating from Ingress to Gateway
*********************************

The Gateway API is not only the long-term successor to the Ingress API ; it also supports use cases beyond HTTP/HTTPS-based applications.

In this section, we will highlight some of the limitations with Ingress, explain some of the benefits of the Gateway API before explaining 
some of the options available with migrating from Ingress API to Gateway API.

Ingress API Limitations
#######################

The development of the Gateway API stemmed from the realization that the Kubernetes Ingress API had some limitations.

- Limited support for advanced routing:
  
The Ingress API supports basic routing based on path and host rules, but it lacks native support for more advanced routing 
features such as traffic splitting, header modification, and URL rewriting.

- Limited protocol support:
  
The Ingress API only supports HTTP and HTTPS traffic, and does not natively support other protocols such as TCP or UDP.
The specification of Ingress API was simply too limited and not extensible enough. To address these technical limitations, 
software vendors and developers created vendor-specific annotations to provide these specific capabilities. But using annotations 
ended up creating inconsistencies from one Ingress Controller to another. This means that, if you wanted to start using a different 
Ingress Controller over another, you would likely face some conversion issues as annotations tend to be vendor-specific.

- Operational constraints:
  
Finally, the Ingress API suffers from operational constraints: it simply is not well-suited for multi-team clusters with shared load-balancing infrastructure.

Benefits of Gateway API
#######################

The Gateway API was designed from the ground up to address the Ingress API limitations. The team behind the Gateway API is a Kubernetes SIG-Network project.

.. note::

    You can find out more information about the project on its `website <https://gateway-api.sigs.k8s.io/>`_.

On the technical front, the Gateway API provides a centralized mechanism for managing and enforcing policies for external traffic, 
including HTTP routing, TLS termination, traffic splitting/weighting, and header modification.

Native support for these features means annotations are no longer needed to provide support for features that are commonly required
for ingress traffic patterns. This means that Gateway API resources are more portable from one Gateway API implementation to another.

When customization is required, Gateway API provides several flexible models, including specific extension points to enable diverse 
traffic patterns. As extensions are added, the Gateway API team will keep looking for common denominators and will promote features 
to the API conformance to avoid going back to some of the chaos seen with extending Ingress API resources.

Finally, the Gateway API implementation was designed with role-based persona in mind. The Ingress model was based on a model where 
it was assumed that developers managed and created Ingress and Services resources themselves.

In many of the more complex deployments however, there are various personas involved:

- Infrastructure Provider: the cloud provider (AWS, Azure, GCP) for example
- Cluster Operator: responsible for the the administration of a cluster
- Application Developer: responsible for defining application configuration and service composition

By decomposing the Ingress API into several Gateway API objects, personas will be assigned the right access and privileges that their responsibilities require.

For example, application developers in a specific team would be allowed to create Route objects in a specified namespace 
but would not be able to modify the Gateway configuration or edit Route objects in namespaces other than theirs.

Migration Methods
#################

There are currently two primary methods to migrate Ingress API resources to Gateway API:

- *manual* - manually creating Gateway API resources based on existing Ingress API resources.
- *automated*, creating rules using the `ingress2gateway tool <https://github.com/kubernetes-sigs/ingress2gateway>`_. 
  This project reads Ingress resources from a Kubernetes cluster based on your current Kube Config. It will output YAML for equivalent Gateway API resources to stdout.

Examples
########

Please refer to one of the below examples on how to migrate to 
Cilium's Gateway API features:

.. toctree::
   :maxdepth: 1
   :glob:

   http-migration
   tls-migration

