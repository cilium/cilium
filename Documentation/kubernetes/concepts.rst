.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

******************
Concepts
******************

.. _k8s_concepts_deployment:

Deployment
==========

The configuration of a standard Cilium Kubernetes deployment consists of
several Kubernetes resources:

* A ``DaemonSet`` resource:  describes the Cilium pod that is deployed to each
  Kubernetes node.  This pod runs the cilium-agent and associated daemons. The
  configuration of this DaemonSet includes the image tag indicating the exact
  version of the Cilium docker container (e.g., v1.0.0) and command-line
  options passed to the cilium-agent.

* A ``ConfigMap`` resource:  describes common configuration values that are
  passed to the cilium-agent, such as the kvstore endpoint and credentials,
  enabling/disabling debug mode, etc.

* ``ServiceAccount``, ``ClusterRole``, and ``ClusterRoleBindings`` resources:
  the identity and permissions used by cilium-agent to access the Kubernetes
  API server when Kubernetes RBAC is enabled.

* A ``Secret`` resource: describes the credentials use access the etcd kvstore,
  if required.
