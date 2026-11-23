.. _gs_clustermesh_global_namespace:

*******************************
ClusterMesh Namespace Export
*******************************

ClusterMesh can limit which namespaces are exported to connected clusters.
This controls whether Cilium endpoint, identity, and service information is
shared across the mesh. A namespace that is not global remains local to its
cluster.

Configuring the default
#######################

The Helm value ``clustermesh.defaultGlobalNamespace`` controls how namespaces
without an explicit annotation are treated. It defaults to ``true``, which
preserves the behavior where all namespaces are global.

To make namespaces local by default, set the value to ``false``:

.. cilium-helm-upgrade::
   :namespace: kube-system
   :extra-args: --reuse-values
   :set: clustermesh.defaultGlobalNamespace=false

Overriding the default for a namespace
######################################

The namespace annotation ``clustermesh.cilium.io/global`` overrides the
default:

* Set it to ``"true"`` to make the namespace global.
* Set it to ``"false"`` to keep the namespace local.

For example, with the default set to ``false``, opt in a namespace:

.. code-block:: shell-session

   kubectl annotate namespace team-a clustermesh.cilium.io/global="true"

To explicitly keep another namespace local, even when the default is
``true``:

.. code-block:: shell-session

   kubectl annotate namespace team-b clustermesh.cilium.io/global="false"

Cross-cluster connectivity and network policy
##############################################

Cilium exports endpoint and identity information only for global namespaces.
For cross-cluster pod-to-pod connectivity and normal label-based network policy
enforcement, both the source and destination pods must therefore be in global
namespaces. If either namespace is local, the peer cluster does not receive the
endpoint and identity information needed to establish that connectivity or
match remote endpoint labels in policy.

This setting is a namespace-level export boundary, not a replacement for
network policy. Continue to use CiliumNetworkPolicy or NetworkPolicy to define
which traffic is allowed between workloads in global namespaces.

Global Services
###############

A Service is a Global Service only when **both** of the following are true:

* Its namespace is global.
* The Service has the annotation
  ``service.cilium.io/global: "true"``.

The Service annotation does not make a local namespace global. See
:ref:`gs_clustermesh_global_services` for Global Service configuration and
load-balancing behavior.

Multi-Cluster Services API
##########################

MCS-API ServiceExports are supported only in global namespaces. When a
ServiceExport is created in a local namespace, Cilium reports that the
namespace is local and does not export the ServiceExport to the ClusterMesh
API server. The corresponding ServiceImport cannot be imported into remote
clusters, and its derived Service is not created.

See :ref:`gs_clustermesh_mcsapi` for MCS-API setup and usage.
