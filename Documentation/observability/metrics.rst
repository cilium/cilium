.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _metrics:

********************
Monitoring & Metrics
********************

Cilium and Hubble can both be configured to serve `Prometheus
<https://prometheus.io>`_ metrics. Prometheus is a pluggable metrics collection
and storage system and can act as a data source for `Grafana
<https://grafana.com/>`_, a metrics visualization frontend. Unlike some metrics
collectors like statsd, Prometheus requires the collectors to pull metrics from
each source.

Cilium and Hubble metrics can be enabled independently of each other.

Cilium Metrics
==============

Cilium metrics provide insights into the state of Cilium itself, namely
of the ``cilium-agent``, ``cilium-envoy``, and ``cilium-operator`` processes.
To run Cilium with Prometheus metrics enabled, deploy it with the
``prometheus.enabled=true`` Helm value set.

Cilium metrics are exported under the ``cilium_`` Prometheus namespace. Envoy
metrics are exported under the ``envoy_`` Prometheus namespace, of which the
Cilium-defined metrics are exported under the ``envoy_cilium_`` namespace.
When running and collecting in Kubernetes they will be tagged with a pod name
and namespace.

Installation
------------

You can enable metrics for ``cilium-agent`` (including Envoy) with the Helm value
``prometheus.enabled=true``. ``cilium-operator`` metrics are enabled by default,
if you want to disable them, set Helm value ``operator.prometheus.enabled=false``.

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set prometheus.enabled=true \\
     --set operator.prometheus.enabled=true

The ports can be configured via ``prometheus.port``,
``envoy.prometheus.port``, or ``operator.prometheus.port`` respectively.

When metrics are enabled, all Cilium components will have the following
annotations. They can be used to signal Prometheus whether to scrape metrics:

.. code-block:: yaml

        prometheus.io/scrape: true
        prometheus.io/port: 9962

To collect Envoy metrics the Cilium chart will create a Kubernetes headless
service named ``cilium-agent`` with the ``prometheus.io/scrape:'true'`` annotation set:

.. code-block:: yaml

        prometheus.io/scrape: true
        prometheus.io/port: 9964

This additional headless service in addition to the other Cilium components is needed
as each component can only have one Prometheus scrape and port annotation.

Prometheus will pick up the Cilium and Envoy metrics automatically if the following
option is set in the ``scrape_configs`` section:

.. code-block:: yaml

    scrape_configs:
    - job_name: 'kubernetes-pods'
      kubernetes_sd_configs:
      - role: pod
      relabel_configs:
        - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
          action: keep
          regex: true
        - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
          action: replace
          regex: ([^:]+)(?::\d+)?;(\d+)
          replacement: ${1}:${2}
          target_label: __address__

Hubble Metrics
==============

While Cilium metrics allow you to monitor the state Cilium itself,
Hubble metrics on the other hand allow you to monitor the network behavior
of your Cilium-managed Kubernetes pods with respect to connectivity and security.

Installation
------------

To deploy Cilium with Hubble metrics enabled, you need to enable Hubble with
``hubble.enabled=true`` and provide a set of Hubble metrics you want to
enable via ``hubble.metrics.enabled``.

Some of the metrics can also be configured with additional options.
See the :ref:`Hubble exported metrics<hubble_exported_metrics>`
section for the full list of available metrics and their options.

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set prometheus.enabled=true \\
     --set operator.prometheus.enabled=true \\
     --set hubble.enabled=true \\
     --set hubble.metrics.enableOpenMetrics=true \\
     --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,httpV2:exemplars=true;labelsContext=source_ip\\,source_namespace\\,source_workload\\,destination_ip\\,destination_namespace\\,destination_workload\\,traffic_direction}"

The port of the Hubble metrics can be configured with the
``hubble.metrics.port`` Helm value.

.. Note::

    L7 metrics such as HTTP, are only emitted for pods that enable
    :ref:`Layer 7 Protocol Visibility <proxy_visibility>`.

When deployed with a non-empty ``hubble.metrics.enabled`` Helm value, the
Cilium chart will create a Kubernetes headless service named ``hubble-metrics``
with the ``prometheus.io/scrape:'true'`` annotation set:

.. code-block:: yaml

        prometheus.io/scrape: true
        prometheus.io/port: 9965

Set the following options in the ``scrape_configs`` section of Prometheus to
have it scrape all Hubble metrics from the endpoints automatically:

.. code-block:: yaml

    scrape_configs:
      - job_name: 'kubernetes-endpoints'
        scrape_interval: 30s
        kubernetes_sd_configs:
          - role: endpoints
        relabel_configs:
          - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape]
            action: keep
            regex: true
          - source_labels: [__address__, __meta_kubernetes_service_annotation_prometheus_io_port]
            action: replace
            target_label: __address__
            regex: (.+)(?::\d+);(\d+)
            replacement: $1:$2

.. _hubble_open_metrics:

OpenMetrics
-----------

Additionally, you can opt-in to `OpenMetrics <https://openmetrics.io>`_ by
setting ``hubble.metrics.enableOpenMetrics=true``.
Enabling OpenMetrics configures the Hubble metrics endpoint to support exporting
metrics in OpenMetrics format when explicitly requested by clients.

Using OpenMetrics supports additional functionality such as Exemplars, which
enables associating metrics with traces by embedding trace IDs into the
exported metrics.

Prometheus needs to be configured to take advantage of OpenMetrics and will
only scrape exemplars when the `exemplars storage feature is enabled
<https://prometheus.io/docs/prometheus/latest/feature_flags/#exemplars-storage>`_.

OpenMetrics imposes a few additional requirements on metrics names and labels,
so this functionality is currently opt-in, though we believe all of the Hubble
metrics conform to the OpenMetrics requirements.


.. _clustermesh_apiserver_metrics:

Cluster Mesh API Server Metrics
===============================

Cluster Mesh API Server metrics provide insights into the state of the
``clustermesh-apiserver`` process, the ``kvstoremesh`` process (if enabled),
and the sidecar etcd instance.
Cluster Mesh API Server metrics are exported under the ``cilium_clustermesh_apiserver_``
Prometheus namespace. KVStoreMesh metrics are exported under the ``cilium_kvstoremesh_``
Prometheus namespace. Etcd metrics are exported under the ``etcd_`` Prometheus namespace.


Installation
------------

You can enable the metrics for different Cluster Mesh API Server components by
setting the following values:

* clustermesh-apiserver: ``clustermesh.apiserver.metrics.enabled=true``
* kvstoremesh: ``clustermesh.apiserver.metrics.kvstoremesh.enabled=true``
* sidecar etcd instance: ``clustermesh.apiserver.metrics.etcd.enabled=true``

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set clustermesh.useAPIServer=true \\
     --set clustermesh.apiserver.metrics.enabled=true \\
     --set clustermesh.apiserver.metrics.kvstoremesh.enabled=true \\
     --set clustermesh.apiserver.metrics.etcd.enabled=true

You can figure the ports by way of ``clustermesh.apiserver.metrics.port``,
``clustermesh.apiserver.metrics.kvstoremesh.port`` and
``clustermesh.apiserver.metrics.etcd.port`` respectively.

You can automatically create a
`Prometheus Operator <https://github.com/prometheus-operator/prometheus-operator>`_
``ServiceMonitor`` by setting ``clustermesh.apiserver.metrics.serviceMonitor.enabled=true``.

Example Prometheus & Grafana Deployment
=======================================

If you don't have an existing Prometheus and Grafana stack running, you can
deploy a stack with:

.. parsed-literal::

    kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/addons/prometheus/monitoring-example.yaml

It will run Prometheus and Grafana in the ``cilium-monitoring`` namespace. If
you have either enabled Cilium or Hubble metrics, they will automatically
be scraped by Prometheus. You can then expose Grafana to access it via your browser.

.. code-block:: shell-session

    kubectl -n cilium-monitoring port-forward service/grafana --address 0.0.0.0 --address :: 3000:3000

Open your browser and access http://localhost:3000/

Metrics Reference
=================

cilium-agent
------------

Configuration
^^^^^^^^^^^^^

To expose any metrics, invoke ``cilium-agent`` with the
``--prometheus-serve-addr`` option. This option takes a ``IP:Port`` pair but
passing an empty IP (e.g. ``:9962``) will bind the server to all available
interfaces (there is usually only one in a container).

To customize ``cilium-agent`` metrics, configure the ``--metrics`` option with
``"+metric_a -metric_b -metric_c"``, where ``+/-`` means to enable/disable
the metric. For example, for really large clusters, users may consider to
disable the following two metrics as they generate too much data:

- ``cilium_node_connectivity_status``
- ``cilium_node_connectivity_latency_seconds``

You can then configure the agent with ``--metrics="-cilium_node_connectivity_status -cilium_node_connectivity_latency_seconds"``.

Exported Metrics
^^^^^^^^^^^^^^^^

Endpoint
~~~~~~~~

============================================ ================================================== ========== ========================================================
Name                                         Labels                                             Default    Description
============================================ ================================================== ========== ========================================================
``endpoint``                                                                                    Enabled    Number of endpoints managed by this agent
``endpoint_max_ifindex``                                                                        Disabled   Maximum interface index observed for existing endpoints
``endpoint_regenerations_total``             ``outcome``                                        Enabled    Count of all endpoint regenerations that have completed
``endpoint_regeneration_time_stats_seconds`` ``scope``                                          Enabled    Endpoint regeneration time stats
``endpoint_state``                           ``state``                                          Enabled    Count of all endpoints
============================================ ================================================== ========== ========================================================

The default enabled status of ``endpoint_max_ifindex`` is dynamic. On earlier
kernels (typically with version lower than 5.10), Cilium must store the
interface index for each endpoint in the conntrack map, which reserves 16 bits
for this field. If Cilium is running on such a kernel, this metric will be
enabled by default. It can be used to implement an alert if the ifindex is
approaching the limit of 65535. This may be the case in instances of
significant Endpoint churn.

Services
~~~~~~~~

========================================== ================================================== ========== ========================================================
Name                                       Labels                                             Default    Description
========================================== ================================================== ========== ========================================================
``services_events_total``                                                                     Enabled    Number of services events labeled by action type
``service_implementation_delay``           ``action``                                         Enabled    Duration in seconds to propagate the data plane programming of a service, its network and endpoints from the time the service or the service pod was changed excluding the event queue latency
========================================== ================================================== ========== ========================================================

Cluster health
~~~~~~~~~~~~~~

========================================== ================================================== ========== ========================================================
Name                                       Labels                                             Default    Description
========================================== ================================================== ========== ========================================================
``unreachable_nodes``                                                                         Enabled    Number of nodes that cannot be reached
``unreachable_health_endpoints``                                                              Enabled    Number of health endpoints that cannot be reached
========================================== ================================================== ========== ========================================================

Node Connectivity
~~~~~~~~~~~~~~~~~

========================================== ====================================================================================================================================================================== ========== ===================================================================================================================
Name                                       Labels                                                                                                                                                                 Default    Description
========================================== ====================================================================================================================================================================== ========== ===================================================================================================================
``node_connectivity_status``               ``source_cluster``, ``source_node_name``, ``target_cluster``, ``target_node_name``, ``target_node_type``, ``type``                                                     Enabled    The last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes
``node_connectivity_latency_seconds``      ``address_type``, ``protocol``, ``source_cluster``, ``source_node_name``, ``target_cluster``, ``target_node_ip``, ``target_node_name``, ``target_node_type``, ``type`` Enabled    The last observed latency between the current Cilium agent and other Cilium nodes in seconds
========================================== ====================================================================================================================================================================== ========== ===================================================================================================================

Clustermesh
~~~~~~~~~~~

=============================================== ============================================================ ========== =================================================================
Name                                            Labels                                                       Default    Description
=============================================== ============================================================ ========== =================================================================
``clustermesh_global_services``                 ``source_cluster``, ``source_node_name``                     Enabled    The total number of global services in the cluster mesh
``clustermesh_remote_clusters``                 ``source_cluster``, ``source_node_name``                     Enabled    The total number of remote clusters meshed with the local cluster
``clustermesh_remote_cluster_failures``         ``source_cluster``, ``source_node_name``, ``target_cluster`` Enabled    The total number of failures related to the remote cluster
``clustermesh_remote_cluster_nodes``            ``source_cluster``, ``source_node_name``, ``target_cluster`` Enabled    The total number of nodes in the remote cluster
``clustermesh_remote_cluster_last_failure_ts``  ``source_cluster``, ``source_node_name``, ``target_cluster`` Enabled    The timestamp of the last failure of the remote cluster
``clustermesh_remote_cluster_readiness_status`` ``source_cluster``, ``source_node_name``, ``target_cluster`` Enabled    The readiness status of the remote cluster
=============================================== ============================================================ ========== =================================================================

Datapath
~~~~~~~~

============================================= ================================================== ========== ========================================================
Name                                          Labels                                             Default    Description
============================================= ================================================== ========== ========================================================
``datapath_conntrack_dump_resets_total``      ``area``, ``name``, ``family``                     Enabled    Number of conntrack dump resets. Happens when a BPF entry gets removed while dumping the map is in progress.
``datapath_conntrack_gc_runs_total``          ``status``                                         Enabled    Number of times that the conntrack garbage collector process was run
``datapath_conntrack_gc_key_fallbacks_total``                                                    Enabled    The number of alive and deleted conntrack entries at the end of a garbage collector run labeled by datapath family
``datapath_conntrack_gc_entries``             ``family``                                         Enabled    The number of alive and deleted conntrack entries at the end of a garbage collector run
``datapath_conntrack_gc_duration_seconds``    ``status``                                         Enabled    Duration in seconds of the garbage collector process
============================================= ================================================== ========== ========================================================

IPsec
~~~~~

============================================= ================================================== ========== ===========================================================
Name                                          Labels                                             Default    Description
============================================= ================================================== ========== ===========================================================
``ipsec_xfrm_error``                          ``error``, ``type``                                Enabled    Total number of xfrm errors
``ipsec_keys``                                                                                   Enabled    Number of keys in use
``ipsec_xfrm_states``                         ``direction``                                      Enabled    Number of XFRM states
``ipsec_xfrm_policies``                       ``direction``                                      Enabled    Number of XFRM policies
============================================= ================================================== ========== ===========================================================

eBPF
~~~~

========================================== ===================================================================== ========== ========================================================
Name                                       Labels                                                                Default    Description
========================================== ===================================================================== ========== ========================================================
``bpf_syscall_duration_seconds``           ``operation``, ``outcome``                                            Disabled   Duration of eBPF system call performed
``bpf_map_ops_total``                      ``mapName`` (deprecated), ``map_name``, ``operation``, ``outcome``    Enabled    Number of eBPF map operations performed. ``mapName`` is deprecated and will be removed in 1.10. Use ``map_name`` instead.
``bpf_map_pressure``                       ``map_name``                                                          Enabled    Map pressure is defined as a ratio of the required map size compared to its configured size. Values < 1.0 indicate the map's utilization, while values >= 1.0 indicate that the map is full. Policy map metrics are only reported when the ratio is over 0.1, ie 10% full.
``bpf_map_capacity``                       ``map_group``                                                         Enabled    Maximum size of eBPF maps by group of maps (type of map that have the same max capacity size). Map types with size of 65536 are not emitted, missing map types can be assumed to be 65536.
``bpf_maps_virtual_memory_max_bytes``                                                                            Enabled    Max memory used by eBPF maps installed in the system
``bpf_progs_virtual_memory_max_bytes``                                                                           Enabled    Max memory used by eBPF programs installed in the system
========================================== ===================================================================== ========== ========================================================

Both ``bpf_maps_virtual_memory_max_bytes`` and ``bpf_progs_virtual_memory_max_bytes``
are currently reporting the system-wide memory usage of eBPF that is directly
and not directly managed by Cilium. This might change in the future and only
report the eBPF memory usage directly managed by Cilium.

Drops/Forwards (L3/L4)
~~~~~~~~~~~~~~~~~~~~~~

========================================== ================================================== ========== ========================================================
Name                                       Labels                                             Default    Description
========================================== ================================================== ========== ========================================================
``drop_count_total``                       ``reason``, ``direction``                          Enabled    Total dropped packets
``drop_bytes_total``                       ``reason``, ``direction``                          Enabled    Total dropped bytes
``forward_count_total``                    ``direction``                                      Enabled    Total forwarded packets
``forward_bytes_total``                    ``direction``                                      Enabled    Total forwarded bytes
========================================== ================================================== ========== ========================================================

Policy
~~~~~~

========================================== ================================================== ========== ========================================================
Name                                       Labels                                             Default    Description
========================================== ================================================== ========== ========================================================
``policy``                                                                                    Enabled    Number of policies currently loaded
``policy_regeneration_total``                                                                 Enabled    Deprecated, will be removed in Cilium 1.17 - use ``endpoint_regenerations_total`` instead. Total number of policies regenerated successfully
``policy_regeneration_time_stats_seconds`` ``scope``                                          Enabled    Deprecated, will be removed in Cilium 1.17 - use ``endpoint_regeneration_time_stats_seconds`` instead. Policy regeneration time stats labeled by the scope
``policy_max_revision``                                                                       Enabled    Highest policy revision number in the agent
``policy_change_total``                                                                       Enabled    Number of policy changes by outcome
``policy_endpoint_enforcement_status``                                                        Enabled    Number of endpoints labeled by policy enforcement status
``policy_implementation_delay``            ``source``                                         Enabled    Time in seconds between a policy change and it being fully deployed into the datapath, labeled by the policy's source
========================================== ================================================== ========== ========================================================

Policy L7 (HTTP/Kafka/FQDN)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

======================================== ================================================== ========== ========================================================
Name                                     Labels                                             Default    Description
======================================== ================================================== ========== ========================================================
``proxy_redirects``                      ``protocol``                                       Enabled    Number of redirects installed for endpoints
``proxy_upstream_reply_seconds``         ``error``, ``protocol_l7``, ``scope``              Enabled    Seconds waited for upstream server to reply to a request
``proxy_datapath_update_timeout_total``                                                     Disabled   Number of total datapath update timeouts due to FQDN IP updates
``policy_l7_total``                      ``rule``, ``proxy_type``                           Enabled    Number of total L7 requests/responses
======================================== ================================================== ========== ========================================================

Identity
~~~~~~~~

======================================== ================================================== ========== ========================================================
Name                                     Labels                                             Default    Description
======================================== ================================================== ========== ========================================================
``identity``                             ``type``                                           Enabled    Number of identities currently allocated
``identity_label_sources``               ``source``                                         Enabled    Number of identities which contain at least one label from the given label source
``ipcache_errors_total``                 ``type``, ``error``                                Enabled    Number of errors interacting with the ipcache
``ipcache_events_total``                 ``type``                                           Enabled    Number of events interacting with the ipcache
======================================== ================================================== ========== ========================================================

Events external to Cilium
~~~~~~~~~~~~~~~~~~~~~~~~~

======================================== ================================================== ========== ========================================================
Name                                     Labels                                             Default    Description
======================================== ================================================== ========== ========================================================
``event_ts``                             ``source``                                         Enabled    Last timestamp when Cilium received an event from a control plane source, per resource and per action
``k8s_event_lag_seconds``                ``source``                                         Disabled   Lag for Kubernetes events - computed value between receiving a CNI ADD event from kubelet and a Pod event received from kube-api-server
======================================== ================================================== ========== ========================================================

Controllers
~~~~~~~~~~~

======================================== ================================================== ========== ========================================================
Name                                     Labels                                             Default    Description
======================================== ================================================== ========== ========================================================
``controllers_runs_total``               ``status``                                         Enabled    Number of times that a controller process was run
``controllers_runs_duration_seconds``    ``status``                                         Enabled    Duration in seconds of the controller process
``controllers_group_runs_total``         ``status``, ``group_name``                         Enabled    Number of times that a controller process was run, labeled by controller group name
``controllers_failing``                                                                     Enabled    Number of failing controllers
======================================== ================================================== ========== ========================================================

The ``controllers_group_runs_total`` metric reports the success and failure
count of each controller within the system, labeled by controller group name
and completion status. Due to the large number of controllers, enabling this
metric is on a per-controller basis. This is configured using an allow-list
which is passed as the ``controller-group-metrics`` configuration flag,
or the ``prometheus.controllerGroupMetrics`` helm value. The current
recommended default set of group names can be found in the values file of
the Cilium Helm chart. The special names "all" and "none" are supported.

SubProcess
~~~~~~~~~~

======================================== ================================================== ========== ========================================================
Name                                     Labels                                             Default    Description
======================================== ================================================== ========== ========================================================
``subprocess_start_total``               ``subsystem``                                      Enabled    Number of times that Cilium has started a subprocess
======================================== ================================================== ========== ========================================================

Kubernetes
~~~~~~~~~~

=========================================== ================================================== ========== ========================================================
Name                                        Labels                                             Default    Description
=========================================== ================================================== ========== ========================================================
``kubernetes_events_received_total``        ``scope``, ``action``, ``validity``, ``equal``     Enabled    Number of Kubernetes events received
``kubernetes_events_total``                 ``scope``, ``action``, ``outcome``                 Enabled    Number of Kubernetes events processed
``k8s_cnp_status_completion_seconds``       ``attempts``, ``outcome``                          Enabled    Duration in seconds in how long it took to complete a CNP status update
``k8s_terminating_endpoints_events_total``                                                     Enabled    Number of terminating endpoint events received from Kubernetes
=========================================== ================================================== ========== ========================================================

Kubernetes Rest Client
~~~~~~~~~~~~~~~~~~~~~~

============================================= ============================================= ========== ===========================================================
Name                                          Labels                                        Default    Description
============================================= ============================================= ========== ===========================================================
``k8s_client_api_latency_time_seconds``       ``path``, ``method``                          Enabled    Duration of processed API calls labeled by path and method
``k8s_client_rate_limiter_duration_seconds``  ``path``, ``method``                          Enabled    Kubernetes client rate limiter latency in seconds. Broken down by path and method
``k8s_client_api_calls_total``                ``host``, ``method``, ``return_code``         Enabled    Number of API calls made to kube-apiserver labeled by host, method and return code
============================================= ============================================= ========== ===========================================================

Kubernetes workqueue
~~~~~~~~~~~~~~~~~~~~

==================================================== ============================================= ========== ===========================================================
Name                                                 Labels                                        Default    Description
==================================================== ============================================= ========== ===========================================================
``k8s_workqueue_depth``                              ``name``                                      Enabled    Current depth of workqueue
``k8s_workqueue_adds_total``                         ``name``                                      Enabled    Total number of adds handled by workqueue
``k8s_workqueue_queue_duration_seconds``             ``name``                                      Enabled    Duration in seconds an item stays in workqueue prior to request
``k8s_workqueue_work_duration_seconds``              ``name``                                      Enabled    Duration in seconds to process an item from workqueue
``k8s_workqueue_unfinished_work_seconds``            ``name``                                      Enabled    Duration in seconds of work in progress that hasn't been observed by work_duration. Large values indicate stuck threads. You can deduce the number of stuck threads by observing the rate at which this value increases.
``k8s_workqueue_longest_running_processor_seconds``  ``name``                                      Enabled    Duration in seconds of the longest running processor for workqueue
``k8s_workqueue_retries_total``                      ``name``                                      Enabled    Total number of retries handled by workqueue
==================================================== ============================================= ========== ===========================================================

IPAM
~~~~

======================================== ============================================ ========== ========================================================
Name                                     Labels                                       Default    Description
======================================== ============================================ ========== ========================================================
``ipam_capacity``                        ``family``                                   Enabled    Total number of IPs in the IPAM pool labeled by family
``ipam_events_total``                                                                 Enabled    Number of IPAM events received labeled by action and datapath family type
``ip_addresses``                         ``family``                                   Enabled    Number of allocated IP addresses
======================================== ============================================ ========== ========================================================

KVstore
~~~~~~~

======================================== ============================================ ========== ========================================================
Name                                     Labels                                       Default    Description
======================================== ============================================ ========== ========================================================
``kvstore_operations_duration_seconds``  ``action``, ``kind``, ``outcome``, ``scope`` Enabled    Duration of kvstore operation
``kvstore_events_queue_seconds``         ``action``, ``scope``                        Enabled    Seconds waited before a received event was queued
``kvstore_quorum_errors_total``          ``error``                                    Enabled    Number of quorum errors
``kvstore_sync_errors_total``            ``scope``, ``source_cluster``                Enabled    Number of times synchronization to the kvstore failed
``kvstore_sync_queue_size``              ``scope``, ``source_cluster``                Enabled    Number of elements queued for synchronization in the kvstore
``kvstore_initial_sync_completed``       ``scope``, ``source_cluster``, ``action``    Enabled    Whether the initial synchronization from/to the kvstore has completed
======================================== ============================================ ========== ========================================================

Agent
~~~~~

================================ ================================ ========== ========================================================
Name                             Labels                           Default    Description
================================ ================================ ========== ========================================================
``agent_bootstrap_seconds``      ``scope``, ``outcome``           Enabled    Duration of various bootstrap phases
``api_process_time_seconds``                                      Enabled    Processing time of all the API calls made to the cilium-agent, labeled by API method, API path and returned HTTP code.
================================ ================================ ========== ========================================================

FQDN
~~~~

================================== ================================ ============ ========================================================
Name                               Labels                           Default      Description
================================== ================================ ============ ========================================================
``fqdn_gc_deletions_total``                                         Enabled      Number of FQDNs that have been cleaned on FQDN garbage collector job
``fqdn_active_names``              ``endpoint``                     Disabled     Number of domains inside the DNS cache that have not expired (by TTL), per endpoint
``fqdn_active_ips``                ``endpoint``                     Disabled     Number of IPs inside the DNS cache associated with a domain that has not expired (by TTL), per endpoint
``fqdn_alive_zombie_connections``  ``endpoint``                     Disabled     Number of IPs associated with domains that have expired (by TTL) yet still associated with an active connection (aka zombie), per endpoint
``fqdn_selectors``                                                  Enabled      Number of registered ToFQDN selectors
================================== ================================ ============ ========================================================

Jobs
~~~~

================================== ================================ ============ ========================================================
Name                               Labels                           Default      Description
================================== ================================ ============ ========================================================
``jobs_errors_total``              ``job``                          Enabled      Number of jobs runs that returned an error
``jobs_one_shot_run_seconds``      ``job``                          Enabled      Histogram of one shot job run duration
``jobs_timer_run_seconds``         ``job``                          Enabled      Histogram of timer job run duration
``jobs_observer_run_seconds``      ``job``                          Enabled      Histogram of observer job run duration
================================== ================================ ============ ========================================================

CIDRGroups
~~~~~~~~~~

=================================================== ===================== =============================
Name                                                Labels                Default    Description
=================================================== ===================== =============================
``cidrgroups_referenced``                                                 Enabled    Number of CNPs and CCNPs referencing at least one CiliumCIDRGroup. CNPs with empty or non-existing CIDRGroupRefs are not considered
``cidrgroup_translation_time_stats_seconds``                              Disabled   CIDRGroup translation time stats
=================================================== ===================== =============================

.. _metrics_api_rate_limiting:

API Rate Limiting
~~~~~~~~~~~~~~~~~

============================================== ========================================== ========== ========================================================
Name                                           Labels                                     Default    Description
============================================== ========================================== ========== ========================================================
``api_limiter_adjustment_factor``              ``api_call``                               Enabled    Most recent adjustment factor for automatic adjustment
``api_limiter_processed_requests_total``       ``api_call``, ``outcome``, ``return_code`` Enabled    Total number of API requests processed
``api_limiter_processing_duration_seconds``    ``api_call``, ``value``                    Enabled    Mean and estimated processing duration in seconds
``api_limiter_rate_limit``                     ``api_call``, ``value``                    Enabled    Current rate limiting configuration (limit and burst)
``api_limiter_requests_in_flight``             ``api_call``  ``value``                    Enabled    Current and maximum allowed number of requests in flight
``api_limiter_wait_duration_seconds``          ``api_call``, ``value``                    Enabled    Mean, min, and max wait duration
``api_limiter_wait_history_duration_seconds``  ``api_call``                               Disabled   Histogram of wait duration per API call processed
============================================== ========================================== ========== ========================================================

.. _metrics_bgp_control_plane:

BGP Control Plane
~~~~~~~~~~~~~~~~~

====================== ============================================= ======== ===================================================================
Name                   Labels                                        Default  Description
====================== ============================================= ======== ===================================================================
``session_state``      ``vrouter``, ``neighbor``                     Enabled  Current state of the BGP session with the peer, Up = 1 or Down = 0
``advertised_routes``  ``vrouter``, ``neighbor``, ``afi``, ``safi``  Enabled  Number of routes advertised to the peer
``received_routes``    ``vrouter``, ``neighbor``, ``afi``, ``safi``  Enabled  Number of routes received from the peer
====================== ============================================= ======== ===================================================================

All metrics are enabled only when the BGP Control Plane is enabled.

cilium-operator
---------------

Configuration
^^^^^^^^^^^^^

``cilium-operator`` can be configured to serve metrics by running with the
option ``--enable-metrics``.  By default, the operator will expose metrics on
port 9963, the port can be changed with the option
``--operator-prometheus-serve-addr``.

Exported Metrics
^^^^^^^^^^^^^^^^

All metrics are exported under the ``cilium_operator_`` Prometheus namespace.

.. _ipam_metrics:

IPAM
~~~~

.. Note::

    IPAM metrics are all ``Enabled`` only if using the AWS, Alibabacloud or Azure IPAM plugins.

======================================== ================================================================= ========== ========================================================
Name                                     Labels                                                            Default    Description
======================================== ================================================================= ========== ========================================================
``ipam_ips``                             ``type``                                                          Enabled    Number of IPs allocated
``ipam_ip_allocation_ops``               ``subnet_id``                                                     Enabled    Number of IP allocation operations.
``ipam_ip_release_ops``                  ``subnet_id``                                                     Enabled    Number of IP release operations.
``ipam_interface_creation_ops``          ``subnet_id``                                                     Enabled    Number of interfaces creation operations.
``ipam_release_duration_seconds``        ``type``, ``status``, ``subnet_id``                               Enabled    Release ip or interface latency in seconds
``ipam_allocation_duration_seconds``     ``type``, ``status``, ``subnet_id``                               Enabled    Allocation ip or interface latency in seconds
``ipam_available_interfaces``                                                                              Enabled    Number of interfaces with addresses available
``ipam_nodes``                           ``category``                                                      Enabled    Number of nodes by category { total | in-deficit | at-capacity }
``ipam_resync_total``                                                                                      Enabled    Number of synchronization operations with external IPAM API
``ipam_api_duration_seconds``            ``operation``, ``response_code``                                  Enabled    Duration of interactions with external IPAM API.
``ipam_api_rate_limit_duration_seconds`` ``operation``                                                     Enabled    Duration of rate limiting while accessing external IPAM API
``ipam_available_ips``                   ``target_node``                                                   Enabled    Number of available IPs on a node (taking into account plugin specific NIC/Address limits).
``ipam_used_ips``                        ``target_node``                                                   Enabled    Number of currently used IPs on a node.
``ipam_needed_ips``                      ``target_node``                                                   Enabled    Number of IPs needed to satisfy allocation on a node.
======================================== ================================================================= ========== ========================================================

LB-IPAM
~~~~~~~

======================================== ================================================================= ========== ========================================================
Name                                     Labels                                                            Default    Description
======================================== ================================================================= ========== ========================================================
``lbipam_conflicting_pools_total``                                                                         Enabled    Number of conflicting pools
``lbipam_ips_available_total``           ``pool``                                                          Enabled    Number of available IPs per pool
``lbipam_ips_used_total``                ``pool``                                                          Enabled    Number of used IPs per pool
``lbipam_services_matching_total``                                                                         Enabled    Number of matching services
``lbipam_services_unsatisfied_total``                                                                      Enabled    Number of services which did not get requested IPs
======================================== ================================================================= ========== ========================================================

Controllers
~~~~~~~~~~~

======================================== ================================================== ========== ========================================================
Name                                     Labels                                             Default    Description
======================================== ================================================== ========== ========================================================
``controllers_group_runs_total``         ``status``, ``group_name``                         Enabled    Number of times that a controller process was run, labeled by controller group name
======================================== ================================================== ========== ========================================================

The ``controllers_group_runs_total`` metric reports the success and failure
count of each controller within the system, labeled by controller group name
and completion status. Due to the large number of controllers, enabling this
metric is on a per-controller basis. This is configured using an allow-list
which is passed as the ``controller-group-metrics`` configuration flag,
or the ``prometheus.controllerGroupMetrics`` helm value. The current
recommended default set of group names can be found in the values file of
the Cilium Helm chart. The special names "all" and "none" are supported.

.. _ces_metrics:

CiliumEndpointSlices (CES)
~~~~~~~~~~~~~~~~~~~~~~~~~~

============================================== ================================ ========================================================
Name                                           Labels                           Description
============================================== ================================ ========================================================
``number_of_ceps_per_ces``                                                      The number of CEPs batched in a CES
``number_of_cep_changes_per_ces``              ``opcode``                       The number of changed CEPs in each CES update
``ces_sync_total``                             ``outcome``                      The number of completed CES syncs by outcome
``ces_queueing_delay_seconds``                                                  CiliumEndpointSlice queueing delay in seconds
============================================== ================================ ========================================================


Hubble
------

Configuration
^^^^^^^^^^^^^

Hubble metrics are served by a Hubble instance running inside ``cilium-agent``.
The command-line options to configure them are ``--enable-hubble``,
``--hubble-metrics-server``, and ``--hubble-metrics``.
``--hubble-metrics-server`` takes an ``IP:Port`` pair, but
passing an empty IP (e.g. ``:9965``) will bind the server to all available
interfaces. ``--hubble-metrics`` takes a comma-separated list of metrics.

Some metrics can take additional semicolon-separated options per metric, e.g.
``--hubble-metrics="dns:query;ignoreAAAA,http:destinationContext=workload-name"``
will enable the ``dns`` metric with the ``query`` and ``ignoreAAAA`` options,
and the ``http`` metric with the ``destinationContext=workload-name`` option.

.. _hubble_context_options:

Context Options
^^^^^^^^^^^^^^^

Hubble metrics support configuration via context options.
Supported context options for all metrics:

- ``sourceContext`` - Configures the ``source`` label on metrics for both egress and ingress traffic.
- ``sourceEgressContext`` - Configures the ``source`` label on metrics for egress traffic (takes precedence over ``sourceContext``).
- ``sourceIngressContext`` - Configures the ``source`` label on metrics for ingress traffic (takes precedence over ``sourceContext``).
- ``destinationContext`` - Configures the ``destination`` label on metrics for both egress and ingress traffic.
- ``destinationEgressContext`` - Configures the ``destination`` label on metrics for egress traffic (takes precedence over ``destinationContext``).
- ``destinationIngressContext`` - Configures the ``destination`` label on metrics for ingress traffic (takes precedence over ``destinationContext``).
- ``labelsContext`` - Configures a list of labels to be enabled on metrics.

There are also some context options that are specific to certain metrics.
See the documentation for the individual metrics to see what options are available for each.

See below for details on each of the different context options.

Most Hubble metrics can be configured to add the source and/or destination
context as a label using the ``sourceContext`` and ``destinationContext``
options. The possible values are:

===================== ===================================================================================
Option Value          Description
===================== ===================================================================================
``identity``          All Cilium security identity labels
``namespace``         Kubernetes namespace name
``pod``               Kubernetes pod name and namespace name in the form of ``namespace/pod``.
``pod-name``          Kubernetes pod name.
``dns``               All known DNS names of the source or destination (comma-separated)
``ip``                The IPv4 or IPv6 address
``reserved-identity`` Reserved identity label.
``workload``          Kubernetes pod's workload name and namespace in the form of ``namespace/workload-name``.
``workload-name``     Kubernetes pod's workload name (workloads are: Deployment, Statefulset, Daemonset, ReplicationController, CronJob, Job, DeploymentConfig (OpenShift), etc).
``app``               Kubernetes pod's app name, derived from pod labels (``app.kubernetes.io/name``, ``k8s-app``, or ``app``).
===================== ===================================================================================

When specifying the source and/or destination context, multiple contexts can be
specified by separating them via the ``|`` symbol.
When multiple are specified, then the first non-empty value is added to the
metric as a label. For example, a metric configuration of
``flow:destinationContext=dns|ip`` will first try to use the DNS name of the
target for the label. If no DNS name is known for the target, it will fall back
and use the IP address of the target instead.

.. note::

   There are 3 cases in which the identity label list contains multiple reserved labels:

   1. ``reserved:kube-apiserver`` and ``reserved:host``
   2. ``reserved:kube-apiserver`` and ``reserved:remote-node``
   3. ``reserved:kube-apiserver`` and ``reserved:world``

   In all of these 3 cases, ``reserved-identity`` context returns ``reserved:kube-apiserver``.

Hubble metrics can also be configured with a ``labelsContext`` which allows providing a list of labels
that should be added to the metric. Unlike ``sourceContext`` and ``destinationContext``, instead
of different values being put into the same metric label, the ``labelsContext`` puts them into different label values.

============================== ===============================================================================
Option Value                   Description
============================== ===============================================================================
``source_ip``                  The source IP of the flow.
``source_namespace``           The namespace of the pod if the flow source is from a Kubernetes pod.
``source_pod``                 The pod name if the flow source is from a Kubernetes pod.
``source_workload``            The name of the source pod's workload (Deployment, Statefulset, Daemonset, ReplicationController, CronJob, Job, DeploymentConfig (OpenShift)).
``source_workload_kind``       The kind of the source pod's workload, for example, Deployment, Statefulset, Daemonset, ReplicationController, CronJob, Job, DeploymentConfig (OpenShift).
``source_app``                 The app name of the source pod, derived from pod labels (``app.kubernetes.io/name``, ``k8s-app``, or ``app``).
``destination_ip``             The destination IP of the flow.
``destination_namespace``      The namespace of the pod if the flow destination is from a Kubernetes pod.
``destination_pod``            The pod name if the flow destination is from a Kubernetes pod.
``destination_workload``       The name of the destination pod's workload (Deployment, Statefulset, Daemonset, ReplicationController, CronJob, Job, DeploymentConfig (OpenShift)).
``destination_workload_kind``  The kind of the destination pod's workload, for example, Deployment, Statefulset, Daemonset, ReplicationController, CronJob, Job, DeploymentConfig (OpenShift).
``destination_app``            The app name of the source pod, derived from pod labels (``app.kubernetes.io/name``, ``k8s-app``, or ``app``).
``traffic_direction``          Identifies the traffic direction of the flow. Possible values are ``ingress``, ``egress`` and ``unknown``.
============================== ===============================================================================

When specifying the flow context, multiple values can be specified by separating them via the ``,`` symbol.
All labels listed are included in the metric, even if empty. For example, a metric configuration of
``http:labelsContext=source_namespace,source_pod`` will add the ``source_namespace`` and ``source_pod``
labels to all Hubble HTTP metrics.

.. note::

    To limit metrics cardinality hubble will remove data series bound to specific pod after one minute from pod deletion.
    Metric is considered to be bound to a specific pod when at least one of the following conditions is met:

    * ``sourceContext`` is set to ``pod`` and metric series has ``source`` label matching ``<pod_namespace>/<pod_name>``
    * ``destinationContext`` is set to ``pod`` and metric series has ``destination`` label matching ``<pod_namespace>/<pod_name>``
    * ``labelsContext`` contains both ``source_namespace`` and ``source_pod`` and metric series labels match namespace and name of deleted pod
    * ``labelsContext`` contains both ``destination_namespace`` and ``destination_pod`` and metric series labels match namespace and name of deleted pod

.. _hubble_exported_metrics:

Exported Metrics
^^^^^^^^^^^^^^^^

Hubble metrics are exported under the ``hubble_`` Prometheus namespace.

lost events
~~~~~~~~~~~

This metric, unlike other ones, is not directly tied to network flows. It's enabled if any of the other metrics is enabled.

================================ ======================================== ========== ==================================================
Name                             Labels                                   Default    Description
================================ ======================================== ========== ==================================================
``lost_events_total``            ``source``                               Enabled    Number of lost events
================================ ======================================== ========== ==================================================

Labels
""""""

- ``source`` identifies the source of lost events, one of:
   - ``perf_event_ring_buffer``
   - ``observer_events_queue``
   - ``hubble_ring_buffer``


``dns``
~~~~~~~

================================ ======================================== ========== ===================================
Name                             Labels                                   Default    Description
================================ ======================================== ========== ===================================
``dns_queries_total``            ``rcode``, ``qtypes``, ``ips_returned``  Disabled   Number of DNS queries observed
``dns_responses_total``          ``rcode``, ``qtypes``, ``ips_returned``  Disabled   Number of DNS responses observed
``dns_response_types_total``     ``type``, ``qtypes``                     Disabled   Number of DNS response types
================================ ======================================== ========== ===================================

Options
"""""""

============== ============= ====================================================================================
Option Key     Option Value  Description
============== ============= ====================================================================================
``query``      N/A           Include the query as label "query"
``ignoreAAAA`` N/A           Ignore any AAAA requests/responses
============== ============= ====================================================================================

This metric supports :ref:`Context Options<hubble_context_options>`.


``drop``
~~~~~~~~

================================ ======================================== ========== ===================================
Name                             Labels                                   Default    Description
================================ ======================================== ========== ===================================
``drop_total``                   ``reason``, ``protocol``                 Disabled   Number of drops
================================ ======================================== ========== ===================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``flow``
~~~~~~~~

================================ ======================================== ========== ===================================
Name                             Labels                                   Default    Description
================================ ======================================== ========== ===================================
``flows_processed_total``        ``type``, ``subtype``, ``verdict``       Disabled   Total number of flows processed
================================ ======================================== ========== ===================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``flows-to-world``
~~~~~~~~~~~~~~~~~~

This metric counts all non-reply flows containing the ``reserved:world`` label in their
destination identity. By default, dropped flows are counted if and only if the drop reason
is ``Policy denied``. Set ``any-drop`` option to count all dropped flows.

================================ ======================================== ========== ============================================
Name                             Labels                                   Default    Description
================================ ======================================== ========== ============================================
``flows_to_world_total``         ``protocol``, ``verdict``                Disabled   Total number of flows to ``reserved:world``.
================================ ======================================== ========== ============================================

Options
"""""""

============== ============= ======================================================
Option Key     Option Value  Description
============== ============= ======================================================
``any-drop``   N/A           Count any dropped flows regardless of the drop reason.
``port``       N/A           Include the destination port as label ``port``.
``syn-only``   N/A           Only count non-reply SYNs for TCP flows.
============== ============= ======================================================


This metric supports :ref:`Context Options<hubble_context_options>`.

``http``
~~~~~~~~

Deprecated, use ``httpV2`` instead.
These metrics can not be enabled at the same time as ``httpV2``.

================================= ======================================= ========== ==============================================
Name                              Labels                                  Default    Description
================================= ======================================= ========== ==============================================
``http_requests_total``           ``method``, ``protocol``, ``reporter``  Disabled   Count of HTTP requests
``http_responses_total``          ``method``, ``status``, ``reporter``    Disabled   Count of HTTP responses
``http_request_duration_seconds`` ``method``, ``reporter``                Disabled   Histogram of HTTP request duration in seconds
================================= ======================================= ========== ==============================================

Labels
""""""

- ``method`` is the HTTP method of the request/response.
- ``protocol`` is the HTTP protocol of the request, (For example: ``HTTP/1.1``, ``HTTP/2``).
- ``status`` is the HTTP status code of the response.
- ``reporter`` identifies the origin of the request/response. It is set to ``client`` if it originated from the client, ``server`` if it originated from the server, or ``unknown`` if its origin is unknown.

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``httpV2``
~~~~~~~~~~

``httpV2`` is an updated version of the existing ``http`` metrics.
These metrics can not be enabled at the same time as ``http``.

The main difference is that ``http_requests_total`` and
``http_responses_total`` have been consolidated, and use the response flow
data.

Additionally, the ``http_request_duration_seconds`` metric source/destination
related labels now are from the perspective of the request. In the ``http``
metrics, the source/destination were swapped, because the metric uses the
response flow data, where the source/destination are swapped, but in ``httpV2``
we correctly account for this.

================================= =================================================== ========== ==============================================
Name                              Labels                                              Default    Description
================================= =================================================== ========== ==============================================
``http_requests_total``           ``method``, ``protocol``, ``status``, ``reporter``  Disabled   Count of HTTP requests
``http_request_duration_seconds`` ``method``, ``reporter``                            Disabled   Histogram of HTTP request duration in seconds
================================= =================================================== ========== ==============================================

Labels
""""""

- ``method`` is the HTTP method of the request/response.
- ``protocol`` is the HTTP protocol of the request, (For example: ``HTTP/1.1``, ``HTTP/2``).
- ``status`` is the HTTP status code of the response.
- ``reporter`` identifies the origin of the request/response. It is set to ``client`` if it originated from the client, ``server`` if it originated from the server, or ``unknown`` if its origin is unknown.

Options
"""""""

============== ============== =============================================================================================================
Option Key     Option Value   Description
============== ============== =============================================================================================================
``exemplars``  ``true``       Include extracted trace IDs in HTTP metrics. Requires :ref:`OpenMetrics to be enabled<hubble_open_metrics>`.
============== ============== =============================================================================================================

This metric supports :ref:`Context Options<hubble_context_options>`.

``icmp``
~~~~~~~~

================================ ======================================== ========== ===================================
Name                             Labels                                   Default    Description
================================ ======================================== ========== ===================================
``icmp_total``                   ``family``, ``type``                     Disabled   Number of ICMP messages
================================ ======================================== ========== ===================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``kafka``
~~~~~~~~~

=================================== ===================================================== ========== ==============================================
Name                                Labels                                                Default    Description
=================================== ===================================================== ========== ==============================================
``kafka_requests_total``            ``topic``, ``api_key``, ``error_code``, ``reporter``  Disabled   Count of Kafka requests by topic
``kafka_request_duration_seconds``  ``topic``, ``api_key``, ``reporter``                  Disabled   Histogram of Kafka request duration by topic
=================================== ===================================================== ========== ==============================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``port-distribution``
~~~~~~~~~~~~~~~~~~~~~

================================ ======================================== ========== ==================================================
Name                             Labels                                   Default    Description
================================ ======================================== ========== ==================================================
``port_distribution_total``      ``protocol``, ``port``                   Disabled   Numbers of packets distributed by destination port
================================ ======================================== ========== ==================================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``tcp``
~~~~~~~

================================ ======================================== ========== ==================================================
Name                             Labels                                   Default    Description
================================ ======================================== ========== ==================================================
``tcp_flags_total``              ``flag``, ``family``                     Disabled   TCP flag occurrences
================================ ======================================== ========== ==================================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

dynamic_exporter_exporters_total
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is dynamic hubble exporter metric.

==================================== ======================================== ========== ==================================================
Name                                 Labels                                   Default    Description
==================================== ======================================== ========== ==================================================
``dynamic_exporter_exporters_total`` ``source``                               Enabled    Number of configured hubble exporters
==================================== ======================================== ========== ==================================================

Labels
""""""

- ``status`` identifies status of exporters, can be one of:
   - ``active``
   - ``inactive``

dynamic_exporter_up
~~~~~~~~~~~~~~~~~~~

This is dynamic hubble exporter metric.

==================================== ======================================== ========== ==================================================
Name                                 Labels                                   Default    Description
==================================== ======================================== ========== ==================================================
``dynamic_exporter_up``              ``source``                               Enabled    Status of exporter (1 - active, 0 - inactive)
==================================== ======================================== ========== ==================================================

Labels
""""""

- ``name`` identifies exporter name

dynamic_exporter_reconfigurations_total
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is dynamic hubble exporter metric.

=========================================== ======================================== ========== ==================================================
Name                                        Labels                                   Default    Description
=========================================== ======================================== ========== ==================================================
``dynamic_exporter_reconfigurations_total`` ``op``                                   Enabled    Number of dynamic exporters reconfigurations
=========================================== ======================================== ========== ==================================================

Labels
""""""

- ``op`` identifies reconfiguration operation type, can be one of:
   - ``add``
   - ``update``
   - ``remove``

dynamic_exporter_config_hash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is dynamic hubble exporter metric.

==================================== ======================================== ========== ==================================================
Name                                 Labels                                   Default    Description
==================================== ======================================== ========== ==================================================
``dynamic_exporter_config_hash``                                              Enabled    Hash of last applied config
==================================== ======================================== ========== ==================================================

dynamic_exporter_config_last_applied
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is dynamic hubble exporter metric.

======================================== ======================================== ========== ==================================================
Name                                     Labels                                   Default    Description
======================================== ======================================== ========== ==================================================
``dynamic_exporter_config_last_applied``                                          Enabled    Timestamp of last applied config
======================================== ======================================== ========== ==================================================




.. _clustermesh_apiserver_metrics_reference:

clustermesh-apiserver
---------------------

Configuration
^^^^^^^^^^^^^

To expose any metrics, invoke ``clustermesh-apiserver`` with the
``--prometheus-serve-addr`` option. This option takes a ``IP:Port`` pair but
passing an empty IP (e.g. ``:9962``) will bind the server to all available
interfaces (there is usually only one in a container).

Exported Metrics
^^^^^^^^^^^^^^^^

All metrics are exported under the ``cilium_clustermesh_apiserver_``
Prometheus namespace.

Bootstrap
~~~~~~~~~

======================================== ============================================ ========================================================
Name                                     Labels                                       Description
======================================== ============================================ ========================================================
``bootstrap_seconds``                    ``source_cluster``                           Duration in seconds to complete bootstrap
======================================== ============================================ ========================================================

KVstore
~~~~~~~

======================================== ============================================ ========================================================
Name                                     Labels                                       Description
======================================== ============================================ ========================================================
``kvstore_operations_duration_seconds``  ``action``, ``kind``, ``outcome``, ``scope`` Duration of kvstore operation
``kvstore_events_queue_seconds``         ``action``, ``scope``                        Seconds waited before a received event was queued
``kvstore_quorum_errors_total``          ``error``                                    Number of quorum errors
``kvstore_sync_errors_total``            ``scope``, ``source_cluster``                Number of times synchronization to the kvstore failed
``kvstore_sync_queue_size``              ``scope``, ``source_cluster``                Number of elements queued for synchronization in the kvstore
``kvstore_initial_sync_completed``       ``scope``, ``source_cluster``, ``action``    Whether the initial synchronization from/to the kvstore has completed
======================================== ============================================ ========================================================

API Rate Limiting
~~~~~~~~~~~~~~~~~

============================================== ========================================== ========================================================
Name                                           Labels                                     Description
============================================== ========================================== ========================================================
``api_limiter_processed_requests_total``       ``api_call``, ``outcome``, ``return_code`` Total number of API requests processed
``api_limiter_processing_duration_seconds``    ``api_call``, ``value``                    Mean and estimated processing duration in seconds
``api_limiter_rate_limit``                     ``api_call``, ``value``                    Current rate limiting configuration (limit and burst)
``api_limiter_requests_in_flight``             ``api_call``  ``value``                    Current and maximum allowed number of requests in flight
``api_limiter_wait_duration_seconds``          ``api_call``, ``value``                     Mean, min, and max wait duration
============================================== ========================================== ========================================================

Controllers
~~~~~~~~~~~

======================================== ================================================== ========== ========================================================
Name                                     Labels                                             Default    Description
======================================== ================================================== ========== ========================================================
``controllers_group_runs_total``         ``status``, ``group_name``                         Enabled    Number of times that a controller process was run, labeled by controller group name
======================================== ================================================== ========== ========================================================

The ``controllers_group_runs_total`` metric reports the success
and failure count of each controller within the system, labeled by
controller group name and completion status. Enabling this metric is
on a per-controller basis. This is configured using an allow-list which
is passed as the ``controller-group-metrics`` configuration flag.
The current default set for ``clustermesh-apiserver`` found in the
Cilium Helm chart is the special name "all", which enables the metric
for all controller groups. The special name "none" is also supported.

.. _kvstoremesh_metrics_reference:

kvstoremesh
-----------

Configuration
^^^^^^^^^^^^^

To expose any metrics, invoke ``kvstoremesh`` with the
``--prometheus-serve-addr`` option. This option takes a ``IP:Port`` pair but
passing an empty IP (e.g. ``:9964``) binds the server to all available
interfaces (there is usually only one interface in a container).

Exported Metrics
^^^^^^^^^^^^^^^^

All metrics are exported under the ``cilium_kvstoremesh_`` Prometheus namespace.

Bootstrap
~~~~~~~~~

======================================== ============================================ ========================================================
Name                                     Labels                                       Description
======================================== ============================================ ========================================================
``bootstrap_seconds``                    ``source_cluster``                           Duration in seconds to complete bootstrap
======================================== ============================================ ========================================================

Remote clusters
~~~~~~~~~~~~~~~

==================================== ======================================= =================================================================
Name                                 Labels                                                       Description
==================================== ======================================= =================================================================
``remote_clusters``                  ``source_cluster``                      The total number of remote clusters meshed with the local cluster
``remote_cluster_failures``          ``source_cluster``, ``target_cluster``  The total number of failures related to the remote cluster
``remote_cluster_last_failure_ts``   ``source_cluster``, ``target_cluster``  The timestamp of the last failure of the remote cluster
``remote_cluster_readiness_status``  ``source_cluster``, ``target_cluster``  The readiness status of the remote cluster
==================================== ======================================= =================================================================

KVstore
~~~~~~~

======================================== ============================================ ========================================================
Name                                     Labels                                       Description
======================================== ============================================ ========================================================
``kvstore_operations_duration_seconds``  ``action``, ``kind``, ``outcome``, ``scope`` Duration of kvstore operation
``kvstore_events_queue_seconds``         ``action``, ``scope``                        Seconds waited before a received event was queued
``kvstore_quorum_errors_total``          ``error``                                    Number of quorum errors
``kvstore_sync_errors_total``            ``scope``, ``source_cluster``                Number of times synchronization to the kvstore failed
``kvstore_sync_queue_size``              ``scope``, ``source_cluster``                Number of elements queued for synchronization in the kvstore
``kvstore_initial_sync_completed``       ``scope``, ``source_cluster``, ``action``    Whether the initial synchronization from/to the kvstore has completed
======================================== ============================================ ========================================================

API Rate Limiting
~~~~~~~~~~~~~~~~~

============================================== ========================================== ========================================================
Name                                           Labels                                     Description
============================================== ========================================== ========================================================
``api_limiter_processed_requests_total``       ``api_call``, ``outcome``, ``return_code`` Total number of API requests processed
``api_limiter_processing_duration_seconds``    ``api_call``, ``value``                    Mean and estimated processing duration in seconds
``api_limiter_rate_limit``                     ``api_call``, ``value``                    Current rate limiting configuration (limit and burst)
``api_limiter_requests_in_flight``             ``api_call``  ``value``                    Current and maximum allowed number of requests in flight
``api_limiter_wait_duration_seconds``          ``api_call``, ``value``                    Mean, min, and max wait duration
============================================== ========================================== ========================================================

Controllers
~~~~~~~~~~~

======================================== ================================================== ========== ========================================================
Name                                     Labels                                             Default    Description
======================================== ================================================== ========== ========================================================
``controllers_group_runs_total``         ``status``, ``group_name``                         Enabled    Number of times that a controller process was run, labeled by controller group name
======================================== ================================================== ========== ========================================================

The ``controllers_group_runs_total`` metric reports the success
and failure count of each controller within the system, labeled by
controller group name and completion status. Enabling this metric is
on a per-controller basis. This is configured using an allow-list
which is passed as the ``controller-group-metrics`` configuration
flag. The current default set for ``kvstoremesh`` found in the
Cilium Helm chart is the special name "all", which enables the metric
for all controller groups. The special name "none" is also supported.

NAT
~~~

.. _nat_metrics:

======================================== ================================================== ========== ========================================================
Name                                     Labels                                             Default    Description
======================================== ================================================== ========== ========================================================
``nat_endpoint_max_connection``          ``family``                                         Enabled    Saturation of the most saturated distinct NAT mapped connection, in terms of egress-IP and remote endpoint address.
======================================== ================================================== ========== ========================================================

These metrics are for monitoring Cilium's NAT mapping functionality. NAT is used by features such as Egress Gateway and BPF masquerading.

The NAT map holds mappings for masqueraded connections. Connection held in the NAT table that are masqueraded with the
same egress-IP and are going to the same remote endpoints IP and port all require a unique source port for the mapping.
This means that any Node masquerading connections to a distinct external endpoint is limited by the possible ephemeral source ports.

Given a Node forwarding one or more such egress-IP and remote endpoint tuples, the ``nat_endpoint_max_connection`` metric is the most saturated such connection in terms of a percent of possible source ports available.
This metric is especially useful when using the egress gateway feature where it's possible to overload a Node if many connections are all going to the same endpoint.
In general, this metric should normally be fairly low.
A high number here may indicate that a Node is reaching its limit for connections to one or more external endpoints.

