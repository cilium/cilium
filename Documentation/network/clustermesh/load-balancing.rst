.. _gs_clustermesh_load_balancing:

**********************************
Load-balancing & Service Discovery
**********************************

Cilium supports two options for cross-cluster service discovery and
load-balancing with Cluster Mesh: :ref:`Multi-Cluster Services API (MCS-API)
<gs_clustermesh_mcsapi>` and :ref:`Global Services <gs_clustermesh_global_services>`.
You can use either option, or both, depending on your needs and environment.

:ref:`MCS-API <gs_clustermesh_mcsapi>` is a Kubernetes SIG Multicluster standard
based on the ServiceExport and ServiceImport resources. It provides higher-level
features such as consistent global service properties, status condition reporting,
and a dedicated ``clusterset.local`` DNS domain, which requires CoreDNS configuration
that Cilium can manage automatically when CoreDNS auto-configuration is enabled.

:ref:`Global Services <gs_clustermesh_global_services>` provide Cilium-specific
cross-cluster load-balancing directly from Service annotations. Global Services
can be simpler to set up in some environments and are useful when you want
different Service properties in each cluster or more granular control over how
backends are shared.

* Use :ref:`MCS-API <gs_clustermesh_mcsapi>` if you want to use a Kubernetes
  SIG Multicluster standard with higher-level features.

* Use :ref:`Global Services <gs_clustermesh_global_services>` if you want to
  directly use Cilium Service annotations or need more granular control.

.. toctree::
   :hidden:
   :maxdepth: 1

   mcsapi
   global-services
