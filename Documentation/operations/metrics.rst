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
``prometheus.enabled=true``. To enable metrics for ``cilium-operator``,
use ``operator.prometheus.enabled=true``.

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set prometheus.enabled=true \\
     --set operator.prometheus.enabled=true

The ports can be configured via ``prometheus.port``,
``proxy.prometheus.port``, or ``operator.prometheus.port`` respectively.

When metrics are enabled, all Cilium components will have the following
annotations. They can be used to signal Prometheus whether to scrape metrics:

.. code-block:: yaml

        prometheus.io/scrape: true
        prometheus.io/port: 9090

To collect Envoy metrics the Cilium chart will create a Kubernetes headless
service named ``cilium-agent`` with the ``prometheus.io/scrape:'true'`` annotation set:

.. code-block:: yaml

        prometheus.io/scrape: true
        prometheus.io/port: 9095

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
          regex: (.+):(?:\d+);(\d+)
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
     --set hubble.metrics.enabled="{dns,drop,tcp,flow,icmp,http}"

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
        prometheus.io/port: 9091

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
passing an empty IP (e.g. ``:9090``) will bind the server to all available
interfaces (there is usually only one in a container).

Exported Metrics
^^^^^^^^^^^^^^^^

Endpoint
~~~~~~~~

============================================ ================================================== ========================================================
Name                                         Labels                                             Description
============================================ ================================================== ========================================================
``endpoint``                                                                                    Number of endpoints managed by this agent
``endpoint_regenerations_total``             ``outcome``                                        Count of all endpoint regenerations that have completed
``endpoint_regeneration_time_stats_seconds`` ``scope``                                          Endpoint regeneration time stats
``endpoint_state``                           ``state``                                          Count of all endpoints
============================================ ================================================== ========================================================

Services
~~~~~~~~

========================================== ================================================== ========================================================
Name                                       Labels                                             Description
========================================== ================================================== ========================================================
``services_events_total``                                                                     Number of services events labeled by action type
========================================== ================================================== ========================================================

Cluster health
~~~~~~~~~~~~~~

========================================== ================================================== ========================================================
Name                                       Labels                                             Description
========================================== ================================================== ========================================================
``unreachable_nodes``                                                                         Number of nodes that cannot be reached
``unreachable_health_endpoints``                                                              Number of health endpoints that cannot be reached
``controllers_failing``                                                                       Number of failing controllers
========================================== ================================================== ========================================================

Node Connectivity
~~~~~~~~~~~~~~~~~

========================================== ====================================================================================================================================================================== ===================================================================================================================
Name                                       Labels                                                                                                                                                                 Description
========================================== ====================================================================================================================================================================== ===================================================================================================================
``node_connectivity_status``               ``source_cluster``, ``source_node_name``, ``target_cluster``, ``target_node_name``, ``target_node_type``, ``type``                                                     The last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes
``node_connectivity_latency_seconds``      ``address_type``, ``protocol``, ``source_cluster``, ``source_node_name``, ``target_cluster``, ``target_node_ip``, ``target_node_name``, ``target_node_type``, ``type`` The last observed latency between the current Cilium agent and other Cilium nodes in seconds
========================================== ====================================================================================================================================================================== ===================================================================================================================

Clustermesh
~~~~~~~~~~~

=============================================== ============================================================ =================================================================
Name                                            Labels                                                       Description
=============================================== ============================================================ =================================================================
``clustermesh_global_services``                 ``source_cluster``, ``source_node_name``                     The total number of global services in the cluster mesh
``clustermesh_remote_clusters``                 ``source_cluster``, ``source_node_name``                     The total number of remote clusters meshed with the local cluster
``clustermesh_remote_cluster_failures``         ``source_cluster``, ``source_node_name``, ``target_cluster`` The total number of failures related to the remote cluster
``clustermesh_remote_cluster_nodes``            ``source_cluster``, ``source_node_name``, ``target_cluster`` The total number of nodes in the remote cluster
``clustermesh_remote_cluster_last_failure_ts``  ``source_cluster``, ``source_node_name``, ``target_cluster`` The timestamp of the last failure of the remote cluster
``clustermesh_remote_cluster_readiness_status`` ``source_cluster``, ``source_node_name``, ``target_cluster`` The readiness status of the remote cluster
=============================================== ============================================================ =================================================================

Datapath
~~~~~~~~

============================================= ================================================== ========================================================
Name                                          Labels                                             Description
============================================= ================================================== ========================================================
``datapath_conntrack_dump_resets_total``      ``area``, ``name``, ``family``                     Number of conntrack dump resets. Happens when a BPF entry gets removed while dumping the map is in progress.
``datapath_conntrack_gc_runs_total``          ``status``                                         Number of times that the conntrack garbage collector process was run
``datapath_conntrack_gc_key_fallbacks_total``                                                    The number of alive and deleted conntrack entries at the end of a garbage collector run labeled by datapath family
``datapath_conntrack_gc_entries``             ``family``                                         The number of alive and deleted conntrack entries at the end of a garbage collector run
``datapath_conntrack_gc_duration_seconds``    ``status``                                         Duration in seconds of the garbage collector process
============================================= ================================================== ========================================================

IPSec
~~~~~

============================================= ================================================== ========================================================
Name                                          Labels                                             Description
============================================= ================================================== ========================================================
``ipsec_xfrm_error``                          ``error``, ``type``                                Total number of xfrm errors.
============================================= ================================================== ========================================================

eBPF
~~~~

========================================== ===================================================================== ========================================================
Name                                       Labels                                                                Description
========================================== ===================================================================== ========================================================
``bpf_syscall_duration_seconds``           ``operation``, ``outcome``                                            Duration of eBPF system call performed
``bpf_map_ops_total``                      ``mapName`` (deprecated), ``map_name``, ``operation``, ``outcome``    Number of eBPF map operations performed. ``mapName`` is deprecated and will be removed in 1.10. Use ``map_name`` instead.
``bpf_map_pressure``                       ``map_name``                                                          Map pressure defined as fill-up ratio of the map. Policy maps are exceptionally reported only when ratio is over 0.1.
``bpf_maps_virtual_memory_max_bytes``                                                                            Max memory used by eBPF maps installed in the system
``bpf_progs_virtual_memory_max_bytes``                                                                           Max memory used by eBPF programs installed in the system
========================================== ===================================================================== ========================================================

Both ``bpf_maps_virtual_memory_max_bytes`` and ``bpf_progs_virtual_memory_max_bytes``
are currently reporting the system-wide memory usage of eBPF that is directly
and not directly managed by Cilium. This might change in the future and only
report the eBPF memory usage directly managed by Cilium.

Drops/Forwards (L3/L4)
~~~~~~~~~~~~~~~~~~~~~~

========================================== ================================================== ========================================================
Name                                       Labels                                             Description
========================================== ================================================== ========================================================
``drop_count_total``                       ``reason``, ``direction``                          Total dropped packets
``drop_bytes_total``                       ``reason``, ``direction``                          Total dropped bytes
``forward_count_total``                    ``direction``                                      Total forwarded packets
``forward_bytes_total``                    ``direction``                                      Total forwarded bytes
========================================== ================================================== ========================================================

Policy
~~~~~~

========================================== ================================================== ========================================================
Name                                       Labels                                             Description
========================================== ================================================== ========================================================
``policy``                                                                                    Number of policies currently loaded
``policy_count``                                                                              Number of policies currently loaded (deprecated, use ``policy``)
``policy_regeneration_total``                                                                 Total number of policies regenerated successfully
``policy_regeneration_time_stats_seconds`` ``scope``                                          Policy regeneration time stats labeled by the scope
``policy_max_revision``                                                                       Highest policy revision number in the agent
``policy_import_errors_total``                                                                Number of times a policy import has failed
``policy_endpoint_enforcement_status``                                                        Number of endpoints labeled by policy enforcement status
========================================== ================================================== ========================================================

Policy L7 (HTTP/Kafka)
~~~~~~~~~~~~~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``proxy_redirects``                      ``protocol``                                       Number of redirects installed for endpoints
``proxy_upstream_reply_seconds``                                                            Seconds waited for upstream server to reply to a request
``proxy_datapath_update_timeout_total``                                                     Number of total datapath update timeouts due to FQDN IP updates
``policy_l7_total``                      ``type``                                           Number of total L7 requests/responses
======================================== ================================================== ========================================================

Identity
~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``identity``                             ``type``                                           Number of identities currently allocated
======================================== ================================================== ========================================================

Events external to Cilium
~~~~~~~~~~~~~~~~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``event_ts``                             ``source``                                         Last timestamp when we received an event
======================================== ================================================== ========================================================

Controllers
~~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``controllers_runs_total``               ``status``                                         Number of times that a controller process was run
``controllers_runs_duration_seconds``    ``status``                                         Duration in seconds of the controller process
======================================== ================================================== ========================================================

SubProcess
~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``subprocess_start_total``               ``subsystem``                                      Number of times that Cilium has started a subprocess
======================================== ================================================== ========================================================

Kubernetes
~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``kubernetes_events_received_total``     ``scope``, ``action``, ``validity``, ``equal``     Number of Kubernetes events received
``kubernetes_events_total``              ``scope``, ``action``, ``outcome``                 Number of Kubernetes events processed
``k8s_cnp_status_completion_seconds``    ``attempts``, ``outcome``                          Duration in seconds in how long it took to complete a CNP status update
======================================== ================================================== ========================================================

IPAM
~~~~

======================================== ============================================ ========================================================
Name                                     Labels                                       Description
======================================== ============================================ ========================================================
``ipam_events_total``                                                                 Number of IPAM events received labeled by action and datapath family type
``ip_addresses``                         ``family``                                   Number of allocated IP addresses
======================================== ============================================ ========================================================

KVstore
~~~~~~~

======================================== ============================================ ========================================================
Name                                     Labels                                       Description
======================================== ============================================ ========================================================
``kvstore_operations_duration_seconds``  ``action``, ``kind``, ``outcome``, ``scope`` Duration of kvstore operation
``kvstore_events_queue_seconds``         ``action``, ``scope``                        Duration of seconds of time received event was blocked before it could be queued
``kvstore_quorum_errors_total``          ``error``                                    Number of quorum errors
======================================== ============================================ ========================================================

Agent
~~~~~

================================ ================================ ========================================================
Name                             Labels                           Description
================================ ================================ ========================================================
``agent_bootstrap_seconds``      ``scope``, ``outcome``           Duration of various bootstrap phases
``api_process_time_seconds``                                      Processing time of all the API calls made to the cilium-agent, labeled by API method, API path and returned HTTP code.
================================ ================================ ========================================================

FQDN
~~~~

================================ ================================ ========================================================
Name                             Labels                           Description
================================ ================================ ========================================================
``qdn_gc_deletions_total``                                        Number of FQDNs that have been cleaned on FQDN garbage collector job
================================ ================================ ========================================================

.. _metrics_api_rate_limiting:

API Rate Limiting
~~~~~~~~~~~~~~~~~

===================================================== ================================ ========================================================
Name                                                  Labels                           Description
===================================================== ================================ ========================================================
``cilium_api_limiter_adjustment_factor``              ``api_call``                     Most recent adjustment factor for automatic adjustment
``cilium_api_limiter_processed_requests_total``       ``api_call``, ``outcome``        Total number of API requests processed
``cilium_api_limiter_processing_duration_seconds``    ``api_call``, ``value``          Mean and estimated processing duration in seconds
``cilium_api_limiter_rate_limit``                     ``api_call``, ``value``          Current rate limiting configuration (limit and burst)
``cilium_api_limiter_requests_in_flight``             ``api_call``  ``value``          Current and maximum allowed number of requests in flight
``cilium_api_limiter_wait_duration_seconds``          ``api_call``, ``value``          Mean, min, and max wait duration
``cilium_api_limiter_wait_history_duration_seconds``  ``api_call``                     Histogram of wait duration per API call processed
===================================================== ================================ ========================================================

cilium-operator
---------------

Configuration
^^^^^^^^^^^^^

``cilium-operator`` can be configured to serve metrics by running with the
option ``--enable-metrics``.  By default, the operator will expose metrics on
port 6942, the port can be changed with the option
``--operator-prometheus-serve-addr``.

Exported Metrics
^^^^^^^^^^^^^^^^

All metrics are exported under the ``cilium_operator_`` Prometheus namespace.

.. _ipam_metrics:

IPAM
~~~~

======================================== ================================================================= ========================================================
Name                                     Labels                                                            Description
======================================== ================================================================= ========================================================
``ipam_ips``                             ``type``                                                          Number of IPs allocated
``ipam_allocation_ops``                  ``subnet_id``                                                     Number of IP allocation operations.
``ipam_interface_creation_ops``          ``subnet_id``, ``status``                                         Number of interfaces creation operations.
``ipam_available``                                                                                         Number of interfaces with addresses available
``ipam_nodes_at_capacity``                                                                                 Number of nodes unable to allocate more addresses
``ipam_resync_total``                                                                                      Number of synchronization operations with external IPAM API
``ipam_api_duration_seconds``            ``operation``, ``response_code``                                  Duration of interactions with external IPAM API.
``ipam_api_rate_limit_duration_seconds`` ``operation``                                                     Duration of rate limiting while accessing external IPAM API
======================================== ================================================================= ========================================================

Hubble
------

Configuration
^^^^^^^^^^^^^

Hubble metrics are served by a Hubble instance running inside ``cilium-agent``.
The command-line options to configure them are ``--enable-hubble``,
``--hubble-metrics-server``, and ``--hubble-metrics``.
``--hubble-metrics-server`` takes an ``IP:Port`` pair, but
passing an empty IP (e.g. ``:9091``) will bind the server to all available
interfaces. ``--hubble-metrics`` takes a comma-separated list of metrics.

Some metrics can take additional semicolon-separated options per metric, e.g.
``--hubble-metrics="dns:query;ignoreAAAA,http:destinationContext=pod-short"``
will enable the ``dns`` metric with the ``query`` and ``ignoreAAAA`` options,
and the ``http`` metric with the ``destinationContext=pod-short`` option.

.. _hubble_context_options:

Context Options
^^^^^^^^^^^^^^^

Most Hubble metrics can be configured to add the source and/or destination
context as a label. The options are called ``sourceContext`` and
``destinationContext``. The possible values are:

============== ====================================================================================
Option Value   Description
============== ====================================================================================
``identity``   All Cilium security identity labels
``namespace``  Kubernetes namespace name
``pod``        Kubernetes pod name
``pod-short``  Short version of the Kubernetes pod name. Typically the deployment/replicaset name.
``dns``        All known DNS names of the source or destination (comma-separated)
``ip``         The IPv4 or IPv6 address
============== ====================================================================================

When specifying the source and/or destination context, multiple contexts can be
specified by separating them via the ``|`` symbol.
When multiple are specified, then the first non-empty value is added to the
metric as a label. For example, a metric configuration of
``flow:destinationContext=dns|ip`` will first try to use the DNS name of the
target for the label. If no DNS name is known for the target, it will fall back
and use the IP address of the target instead.

.. _hubble_exported_metrics:

Exported Metrics
^^^^^^^^^^^^^^^^

Hubble metrics are exported under the ``hubble_`` Prometheus namespace.

``dns``
~~~~~~~

================================ ======================================== ===================================
Name                             Labels                                   Description
================================ ======================================== ===================================
``dns_queries_total``            ``rcode``, ``qtypes``, ``ips_returned``  Number of DNS queries observed
``dns_responses_total``          ``rcode``, ``qtypes``, ``ips_returned``  Number of DNS responses observed
``dns_response_types_total``     ``type``, ``qtypes``                     Number of DNS response types
================================ ======================================== ===================================

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

================================ ======================================== ===================================
Name                             Labels                                   Description
================================ ======================================== ===================================
``drop_total``                   ``reason``, ``protocol``                 Number of drops
================================ ======================================== ===================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``flow``
~~~~~~~~

================================ ======================================== ===================================
Name                             Labels                                   Description
================================ ======================================== ===================================
``flows_processed_total``        ``type``, ``subtype``, ``verdict``       Total number of flows processed
================================ ======================================== ===================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``flows-to-world``
~~~~~~~~~~~~~~~~~~

This metric counts all non-reply flows containing the ``reserved:world`` label in their
destination identity. By default, dropped flows are counted if and only if the drop reason
is ``Policy denied``. Set ``any-drop`` option to count all dropped flows.

================================ ======================================== ============================================
Name                             Labels                                   Description
================================ ======================================== ============================================
``flows_to_world_total``         ``protocol``, ``verdict``                Total number of flows to ``reserved:world``.
================================ ======================================== ============================================

Options
"""""""

============== ============= ======================================================
Option Key     Option Value  Description
============== ============= ======================================================
``any-drop``   N/A           Count any dropped flows regardless of the drop reason.
``port``       N/A           Include the destination port as label ``port``.
============== ============= ======================================================


This metric supports :ref:`Context Options<hubble_context_options>`.

``http``
~~~~~~~~

================================= ============================= ==============================================
Name                              Labels                        Description
================================= ============================= ==============================================
``http_requests_total``           ``method``, ``protocol``      Count of HTTP requests
``http_responses_total``          ``method``, ``status``        Count of HTTP responses
``http_request_duration_seconds`` ``method``                    Quantiles of HTTP request duration in seconds
================================= ============================= ==============================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``icmp``
~~~~~~~~

================================ ======================================== ===================================
Name                             Labels                                   Description
================================ ======================================== ===================================
``icmp_total``                   ``family``, ``type``                     Number of ICMP messages
================================ ======================================== ===================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``port-distribution``
~~~~~~~~~~~~~~~~~~~~~

================================ ======================================== ==================================================
Name                             Labels                                   Description
================================ ======================================== ==================================================
``port_distribution_total``      ``protocol``, ``port``                   Numbers of packets distributed by destination port
================================ ======================================== ==================================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.

``tcp``
~~~~~~~

================================ ======================================== ==================================================
Name                             Labels                                   Description
================================ ======================================== ==================================================
``tcp_flags_total``              ``flag``, ``family``                     TCP flag occurrences
================================ ======================================== ==================================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.
