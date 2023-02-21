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

Agent
~~~~~
+----------------------------------+-------------------------------------+--------+-----------+
|Name                              |Labels                               |Default |Description|
+==================================+=====================================+========+===========+
|``agent_api_process_time_seconds``|``path``, ``method``, ``return_code``|Enabled |           |
+----------------------------------+-------------------------------------+--------+-----------+
|``agent_bootstrap_seconds``       |``scope``, ``outcome``               |Enabled |           |
+----------------------------------+-------------------------------------+--------+-----------+

Agent Labels
""""""""""""

+---------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|Name           |Description                                                                                                                                                                              |Known Value|Value Description|
+===============+=========================================================================================================================================================================================+===========+=================+
|``method``     |The HTTP method                                                                                                                                                                          |           |                 |
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|``outcome``    |Indicates whether the outcome of the operation was successful or not                                                                                                                     |``fail``   |                 |
|               |                                                                                                                                                                                         +-----------+-----------------+
|               |                                                                                                                                                                                         |``success``|                 |
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|``path``       |The API path                                                                                                                                                                             |           |                 |
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|``return_code``|The HTTP code returned for that API path                                                                                                                                                 |           |                 |
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|``scope``      |Used to defined multiples scopes in the same. For example, one counter may measure a metric over the scope of the entire event (scope=global), or just part of an event (scope=slow_path)|           |                 |
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+

API Limiter
~~~~~~~~~~~
+---------------------------------------------+-------------------------+--------+-----------+
|Name                                         |Labels                   |Default |Description|
+=============================================+=========================+========+===========+
|``api_limiter_adjustment_factor``            |``api_call``             |Enabled |           |
+---------------------------------------------+-------------------------+--------+-----------+
|``api_limiter_processed_requests_total``     |``api_call``, ``outcome``|Enabled |           |
+---------------------------------------------+-------------------------+--------+-----------+
|``api_limiter_processing_duration_seconds``  |``api_call``, ``value``  |Enabled |           |
+---------------------------------------------+-------------------------+--------+-----------+
|``api_limiter_rate_limit``                   |``api_call``, ``value``  |Enabled |           |
+---------------------------------------------+-------------------------+--------+-----------+
|``api_limiter_requests_in_flight``           |``api_call``, ``value``  |Enabled |           |
+---------------------------------------------+-------------------------+--------+-----------+
|``api_limiter_wait_duration_seconds``        |``api_call``, ``value``  |Enabled |           |
+---------------------------------------------+-------------------------+--------+-----------+
|``api_limiter_wait_history_duration_seconds``|``api_call``             |Disabled|           |
+---------------------------------------------+-------------------------+--------+-----------+

API Limiter Labels
""""""""""""""""""

+-----------+--------------------------------------------------------------------+-----------+-----------------+
|Name       |Description                                                         |Known Value|Value Description|
+===========+====================================================================+===========+=================+
|``outcome``|Indicates whether the outcome of the operation was successful or not|``fail``   |                 |
|           |                                                                    +-----------+-----------------+
|           |                                                                    |``success``|                 |
+-----------+--------------------------------------------------------------------+-----------+-----------------+

eBPF
~~~~
Both ``bpf_maps_virtual_memory_max_bytes`` and ``bpf_progs_virtual_memory_max_bytes`` are currently reporting the system-wide memory usage of eBPF that is directly and not directly managed by Cilium. This might change in the future and only report the eBPF memory usage directly managed by Cilium.

+--------------------------------+----------------------------------------+--------+-----------+
|Name                            |Labels                                  |Default |Description|
+================================+========================================+========+===========+
|``bpf_map_ops_total``           |``map_name``, ``operation``, ``outcome``|Enabled |           |
+--------------------------------+----------------------------------------+--------+-----------+
|``bpf_map_pressure``            |``map_name``                            |Enabled |           |
+--------------------------------+----------------------------------------+--------+-----------+
|``bpf_syscall_duration_seconds``|``operation``, ``outcome``              |Disabled|           |
+--------------------------------+----------------------------------------+--------+-----------+

eBPF Labels
"""""""""""

+-------------+--------------------------------------------------------------------+-----------+-----------------+
|Name         |Description                                                         |Known Value|Value Description|
+=============+====================================================================+===========+=================+
|``map_name`` |The label for the BPF map name                                      |           |                 |
+-------------+--------------------------------------------------------------------+-----------+-----------------+
|``operation``|The label for BPF maps operations                                   |           |                 |
+-------------+--------------------------------------------------------------------+-----------+-----------------+
|``outcome``  |Indicates whether the outcome of the operation was successful or not|``fail``   |                 |
|             |                                                                    +-----------+-----------------+
|             |                                                                    |``success``|                 |
+-------------+--------------------------------------------------------------------+-----------+-----------------+

Clustermesh
~~~~~~~~~~~
+-----------------------------------------------+------------------------------------------------------------+--------+-----------+
|Name                                           |Labels                                                      |Default |Description|
+===============================================+============================================================+========+===========+
|``clustermesh_global_services``                |``source_cluster``, ``source_node_name``                    |Disabled|           |
+-----------------------------------------------+------------------------------------------------------------+--------+-----------+
|``clustermesh_remote_cluster_failures``        |``source_cluster``, ``source_node_name``, ``target_cluster``|Disabled|           |
+-----------------------------------------------+------------------------------------------------------------+--------+-----------+
|``clustermesh_remote_cluster_last_failure_ts`` |``source_cluster``, ``source_node_name``, ``target_cluster``|Disabled|           |
+-----------------------------------------------+------------------------------------------------------------+--------+-----------+
|``clustermesh_remote_cluster_nodes``           |``source_cluster``, ``source_node_name``, ``target_cluster``|Disabled|           |
+-----------------------------------------------+------------------------------------------------------------+--------+-----------+
|``clustermesh_remote_cluster_readiness_status``|``source_cluster``, ``source_node_name``, ``target_cluster``|Disabled|           |
+-----------------------------------------------+------------------------------------------------------------+--------+-----------+
|``clustermesh_remote_clusters``                |``source_cluster``, ``source_node_name``                    |Disabled|           |
+-----------------------------------------------+------------------------------------------------------------+--------+-----------+

Clustermesh Labels
""""""""""""""""""

+--------------------+---------------------------------+-----------+-----------------+
|Name                |Description                      |Known Value|Value Description|
+====================+=================================+===========+=================+
|``source_cluster``  |The label for source cluster name|           |                 |
+--------------------+---------------------------------+-----------+-----------------+
|``source_node_name``|The label for source node name   |           |                 |
+--------------------+---------------------------------+-----------+-----------------+
|``target_cluster``  |The label for target cluster name|           |                 |
+--------------------+---------------------------------+-----------+-----------------+

Datapath
~~~~~~~~
+---------------------------------------------+-------------------------------------+--------+-----------+
|Name                                         |Labels                               |Default |Description|
+=============================================+=====================================+========+===========+
|``datapath_conntrack_dump_resets_total``     |``area``, ``name``, ``family``       |Enabled |           |
+---------------------------------------------+-------------------------------------+--------+-----------+
|``datapath_conntrack_gc_duration_seconds``   |``family``, ``protocol``, ``status`` |Enabled |           |
+---------------------------------------------+-------------------------------------+--------+-----------+
|``datapath_conntrack_gc_entries``            |``family``, ``protocol``, ``status`` |Enabled |           |
+---------------------------------------------+-------------------------------------+--------+-----------+
|``datapath_conntrack_gc_key_fallbacks_total``|``family``, ``protocol``             |Enabled |           |
+---------------------------------------------+-------------------------------------+--------+-----------+
|``datapath_conntrack_gc_runs_total``         |``family``, ``protocol``, ``status`` |Enabled |           |
+---------------------------------------------+-------------------------------------+--------+-----------+
|``datapath_nat_gc_entries``                  |``family``, ``direction``, ``status``|Enabled |           |
+---------------------------------------------+-------------------------------------+--------+-----------+
|``datapath_signals_handled_total``           |``signal``, ``data``, ``status``     |Enabled |           |
+---------------------------------------------+-------------------------------------+--------+-----------+

Datapath Labels
"""""""""""""""

+-------------+-----------------------------------------------------------------------------------------------------+-----------+-----------------+
|Name         |Description                                                                                          |Known Value|Value Description|
+=============+=====================================================================================================+===========+=================+
|``area``     |Marks which area the metrics are related to (for example, which BPF map)                             |           |                 |
+-------------+-----------------------------------------------------------------------------------------------------+-----------+-----------------+
|``data``     |Marks the signal data                                                                                |           |                 |
+-------------+-----------------------------------------------------------------------------------------------------+-----------+-----------------+
|``direction``|The label for traffic direction                                                                      |           |                 |
+-------------+-----------------------------------------------------------------------------------------------------+-----------+-----------------+
|``family``   |Marks which protocol family (IPv4, IPV6) the metric is related to.                                   |           |                 |
+-------------+-----------------------------------------------------------------------------------------------------+-----------+-----------------+
|``name``     |marks a unique identifier for this metric. The name should be defined once for a given type of error.|           |                 |
+-------------+-----------------------------------------------------------------------------------------------------+-----------+-----------------+
|``protocol`` |Marks the L4 protocol (TCP, ANY) for the metric.                                                     |           |                 |
+-------------+-----------------------------------------------------------------------------------------------------+-----------+-----------------+
|``signal``   |Marks the signal name                                                                                |           |                 |
+-------------+-----------------------------------------------------------------------------------------------------+-----------+-----------------+
|``status``   |The label from completed task                                                                        |           |                 |
+-------------+-----------------------------------------------------------------------------------------------------+-----------+-----------------+

FQDN
~~~~
+---------------------------------+------------+--------+-----------+
|Name                             |Labels      |Default |Description|
+=================================+============+========+===========+
|``fqdn_active_ips``              |``endpoint``|Disabled|           |
+---------------------------------+------------+--------+-----------+
|``fqdn_active_names``            |``endpoint``|Disabled|           |
+---------------------------------+------------+--------+-----------+
|``fqdn_alive_zombie_connections``|``endpoint``|Disabled|           |
+---------------------------------+------------+--------+-----------+
|``fqdn_gc_deletions_total``      |            |Enabled |           |
+---------------------------------+------------+--------+-----------+
|``fqdn_semaphore_rejected_total``|            |Disabled|           |
+---------------------------------+------------+--------+-----------+

IPCache
~~~~~~~
+------------------------+-------------------+--------+-----------+
|Name                    |Labels             |Default |Description|
+========================+===================+========+===========+
|``ipcache_errors_total``|``type``, ``error``|Enabled |           |
+------------------------+-------------------+--------+-----------+
|``ipcache_events_total``|``type``           |Enabled |           |
+------------------------+-------------------+--------+-----------+

IPCache Labels
""""""""""""""

+---------+------------------------------------+-----------+-----------------+
|Name     |Description                         |Known Value|Value Description|
+=========+====================================+===========+=================+
|``error``|Indicates the type of error (string)|           |                 |
+---------+------------------------------------+-----------+-----------------+

Kubernetes
~~~~~~~~~~
+------------------------------------------+-------------------------+--------+-----------+
|Name                                      |Labels                   |Default |Description|
+==========================================+=========================+========+===========+
|``k8s_cnp_status_completion_seconds``     |``attempts``, ``outcome``|Enabled |           |
+------------------------------------------+-------------------------+--------+-----------+
|``k8s_terminating_endpoints_events_total``|                         |Enabled |           |
+------------------------------------------+-------------------------+--------+-----------+

Kubernetes Labels
"""""""""""""""""

+------------+--------------------------------------------------------------------+-----------+-----------------+
|Name        |Description                                                         |Known Value|Value Description|
+============+====================================================================+===========+=================+
|``attempts``|The number of attempts it took to complete the operation            |           |                 |
+------------+--------------------------------------------------------------------+-----------+-----------------+
|``outcome`` |Indicates whether the outcome of the operation was successful or not|``fail``   |                 |
|            |                                                                    +-----------+-----------------+
|            |                                                                    |``success``|                 |
+------------+--------------------------------------------------------------------+-----------+-----------------+

Kubernetes Client
~~~~~~~~~~~~~~~~~
+---------------------------------------+-------------------------------------+--------+-----------+
|Name                                   |Labels                               |Default |Description|
+=======================================+=====================================+========+===========+
|``k8s_client_api_calls_total``         |``host``, ``method``, ``return_code``|Enabled |           |
+---------------------------------------+-------------------------------------+--------+-----------+
|``k8s_client_api_latency_time_seconds``|``path``, ``method``                 |Enabled |           |
+---------------------------------------+-------------------------------------+--------+-----------+

Kubernetes Client Labels
""""""""""""""""""""""""

+---------------+----------------------------------------+-----------+-----------------+
|Name           |Description                             |Known Value|Value Description|
+===============+========================================+===========+=================+
|``method``     |The HTTP method                         |           |                 |
+---------------+----------------------------------------+-----------+-----------------+
|``path``       |The API path                            |           |                 |
+---------------+----------------------------------------+-----------+-----------------+
|``return_code``|The HTTP code returned for that API path|           |                 |
+---------------+----------------------------------------+-----------+-----------------+

KVStore
~~~~~~~
+---------------------------------------+--------------------------------------------+--------+-----------+
|Name                                   |Labels                                      |Default |Description|
+=======================================+============================================+========+===========+
|``kvstore_events_queue_seconds``       |``scope``, ``action``                       |Enabled |           |
+---------------------------------------+--------------------------------------------+--------+-----------+
|``kvstore_operations_duration_seconds``|``scope``, ``kind``, ``action``, ``outcome``|Enabled |           |
+---------------------------------------+--------------------------------------------+--------+-----------+
|``kvstore_quorum_errors_total``        |``error``                                   |Enabled |           |
+---------------------------------------+--------------------------------------------+--------+-----------+

KVStore Labels
""""""""""""""

+-----------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|Name       |Description                                                                                                                                                                              |Known Value|Value Description|
+===========+=========================================================================================================================================================================================+===========+=================+
|``action`` |The label used to defined what kind of action was performed in a metric                                                                                                                  |           |                 |
+-----------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|``error``  |Indicates the type of error (string)                                                                                                                                                     |           |                 |
+-----------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|``kind``   |The kind of a label                                                                                                                                                                      |           |                 |
+-----------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|``outcome``|Indicates whether the outcome of the operation was successful or not                                                                                                                     |``fail``   |                 |
|           |                                                                                                                                                                                         +-----------+-----------------+
|           |                                                                                                                                                                                         |``success``|                 |
+-----------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+
|``scope``  |Used to defined multiples scopes in the same. For example, one counter may measure a metric over the scope of the entire event (scope=global), or just part of an event (scope=slow_path)|           |                 |
+-----------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+-----------------+

Misc
~~~~
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|Name                                        |Labels                                                                                                                                                                |Default |Description|
+============================================+======================================================================================================================================================================+========+===========+
|``controllers_runs_duration_seconds``       |``status``                                                                                                                                                            |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``controllers_runs_total``                  |``status``                                                                                                                                                            |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``drop_bytes_total``                        |``reason``, ``direction``                                                                                                                                             |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``drop_count_total``                        |``reason``, ``direction``                                                                                                                                             |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``endpoint_propagation_delay_seconds``      |                                                                                                                                                                      |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``endpoint_regeneration_time_stats_seconds``|``scope``, ``status``                                                                                                                                                 |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``endpoint_regenerations_total``            |``outcome``                                                                                                                                                           |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``endpoint_state``                          |``endpoint_state``                                                                                                                                                    |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``errors_warnings_total``                   |``level``, ``subsystem``                                                                                                                                              |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``event_ts``                                |``source``, ``scope``, ``action``                                                                                                                                     |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``forward_bytes_total``                     |``direction``                                                                                                                                                         |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``forward_count_total``                     |``direction``                                                                                                                                                         |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``identity``                                |``type``                                                                                                                                                              |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``ipam_events_total``                       |``action``, ``family``                                                                                                                                                |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``k8s_event_lag_seconds``                   |``source``                                                                                                                                                            |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``kubernetes_events_received_total``        |``scope``, ``action``, ``valid``, ``equal``                                                                                                                           |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``kubernetes_events_total``                 |``scope``, ``action``, ``status``                                                                                                                                     |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``node_connectivity_latency_seconds``       |``source_cluster``, ``source_node_name``, ``target_cluster``, ``target_node_name``, ``target_node_ip``, ``target_node_type``, ``type``, ``protocol``, ``address_type``|Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``node_connectivity_status``                |``source_cluster``, ``source_node_name``, ``target_cluster``, ``target_node_name``, ``target_node_type``, ``type``                                                    |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``policy``                                  |                                                                                                                                                                      |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``policy_change_total``                     |``outcome``                                                                                                                                                           |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``policy_endpoint_enforcement_status``      |``enforcement``                                                                                                                                                       |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``policy_implementation_delay``             |``source``                                                                                                                                                            |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``policy_import_errors_total``              |                                                                                                                                                                      |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``policy_max_revision``                     |                                                                                                                                                                      |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``policy_regeneration_time_stats_seconds``  |``scope``, ``status``                                                                                                                                                 |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``policy_regeneration_total``               |                                                                                                                                                                      |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``proxy_datapath_update_timeout_total``     |                                                                                                                                                                      |Disabled|           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``proxy_upstream_reply_seconds``            |``error``, ``protocol_l7``, ``scope``                                                                                                                                 |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``services_events_total``                   |``action``                                                                                                                                                            |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``subprocess_start_total``                  |``subsystem``                                                                                                                                                         |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+
|``version``                                 |``version``                                                                                                                                                           |Enabled |           |
+--------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----------+

Misc Labels
"""""""""""

+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|Name                |Description                                                                                                                                                                              |Known Value|Value Description                                  |
+====================+=========================================================================================================================================================================================+===========+===================================================+
|``action``          |The label used to defined what kind of action was performed in a metric                                                                                                                  |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``direction``       |The label for traffic direction                                                                                                                                                          |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``enforcement``     |The label used to see the enforcement status                                                                                                                                             |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``family``          |Marks which protocol family (IPv4, IPV6) the metric is related to.                                                                                                                       |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``level``           |Log level                                                                                                                                                                                |``error``  |                                                   |
|                    |                                                                                                                                                                                         +-----------+---------------------------------------------------+
|                    |                                                                                                                                                                                         |``warning``|                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``protocol``        |Marks the L4 protocol (TCP, ANY) for the metric.                                                                                                                                         |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``protocol_l7``     |The label used when working with layer 7 protocols.                                                                                                                                      |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``scope``           |Used to defined multiples scopes in the same. For example, one counter may measure a metric over the scope of the entire event (scope=global), or just part of an event (scope=slow_path)|           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``source``          |The source of a label for event metrics i.e. k8s, containerd, api.                                                                                                                       |``api``    |Marks event-related metrics that come from the API |
|                    |                                                                                                                                                                                         +-----------+---------------------------------------------------+
|                    |                                                                                                                                                                                         |``docker`` |Marks event-related metrics that come from docker  |
|                    |                                                                                                                                                                                         +-----------+---------------------------------------------------+
|                    |                                                                                                                                                                                         |``fqdn``   |Marks event-related metrics that come from pkg/fqdn|
|                    |                                                                                                                                                                                         +-----------+---------------------------------------------------+
|                    |                                                                                                                                                                                         |``k8s``    |Marks event-related metrics that come from k8s     |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``source_cluster``  |The label for source cluster name                                                                                                                                                        |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``source_node_name``|The label for source node name                                                                                                                                                           |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``status``          |The label from completed task                                                                                                                                                            |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``subsystem``       |The label used to refer to any of the child process started by cilium (Envoy, monitor, etc..)                                                                                            |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``target_cluster``  |The label for target cluster name                                                                                                                                                        |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``target_node_ip``  |The label for target node IP                                                                                                                                                             |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``target_node_name``|The label for target node name                                                                                                                                                           |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``target_node_type``|The label for target node type (local_node, remote_intra_cluster, vs remote_inter_cluster)                                                                                               |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+
|``version``         |The label for the version number                                                                                                                                                         |           |                                                   |
+--------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------------------------------------------+

Node Neighbor
~~~~~~~~~~~~~
+------------------------------------+----------+--------+-----------+
|Name                                |Labels    |Default |Description|
+====================================+==========+========+===========+
|``node_neigh_arping_requests_total``|``status``|Enabled |           |
+------------------------------------+----------+--------+-----------+

Node Neighbor Labels
""""""""""""""""""""

+----------+-----------------------------+-----------+-----------------+
|Name      |Description                  |Known Value|Value Description|
+==========+=============================+===========+=================+
|``status``|The label from completed task|           |                 |
+----------+-----------------------------+-----------+-----------------+

Nodes
~~~~~
+----------------------------------------+--------------------------+--------+-----------+
|Name                                    |Labels                    |Default |Description|
+========================================+==========================+========+===========+
|``nodes_all_datapath_validations_total``|                          |Enabled |           |
+----------------------------------------+--------------------------+--------+-----------+
|``nodes_all_events_received_total``     |``event_type``, ``source``|Enabled |           |
+----------------------------------------+--------------------------+--------+-----------+
|``nodes_all_num``                       |                          |Enabled |           |
+----------------------------------------+--------------------------+--------+-----------+

Policy L7 (HTTP/Kafka)
~~~~~~~~~~~~~~~~~~~~~~
+--------------------------------+---------------+--------+-----------+
|Name                            |Labels         |Default |Description|
+================================+===============+========+===========+
|``policy_l7_denied_total``      |               |Enabled |           |
+--------------------------------+---------------+--------+-----------+
|``policy_l7_forwarded_total``   |               |Enabled |           |
+--------------------------------+---------------+--------+-----------+
|``policy_l7_parse_errors_total``|               |Enabled |           |
+--------------------------------+---------------+--------+-----------+
|``policy_l7_received_total``    |               |Enabled |           |
+--------------------------------+---------------+--------+-----------+
|``policy_l7_total``             |``rule``       |Enabled |           |
+--------------------------------+---------------+--------+-----------+
|``proxy_redirects``             |``protocol_l7``|Enabled |           |
+--------------------------------+---------------+--------+-----------+

Policy L7 (HTTP/Kafka) Labels
"""""""""""""""""""""""""""""

+---------------+---------------------------------------------------+-----------+-----------------+
|Name           |Description                                        |Known Value|Value Description|
+===============+===================================================+===========+=================+
|``protocol_l7``|The label used when working with layer 7 protocols.|           |                 |
+---------------+---------------------------------------------------+-----------+-----------------+

Triggers
~~~~~~~~
+------------------------------------------------+----------+--------+-----------+
|Name                                            |Labels    |Default |Description|
+================================================+==========+========+===========+
|``triggers_policy_update_call_duration_seconds``|``type``  |Enabled |           |
+------------------------------------------------+----------+--------+-----------+
|``triggers_policy_update_folds``                |          |Enabled |           |
+------------------------------------------------+----------+--------+-----------+
|``triggers_policy_update_total``                |``reason``|Enabled |           |
+------------------------------------------------+----------+--------+-----------+



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
``ipam_nodes_at_capacity``                                                                                 Enabled    Number of nodes unable to allocate more addresses
``ipam_resync_total``                                                                                      Enabled    Number of synchronization operations with external IPAM API
``ipam_api_duration_seconds``            ``operation``, ``response_code``                                  Enabled    Duration of interactions with external IPAM API.
``ipam_api_rate_limit_duration_seconds`` ``operation``                                                     Enabled    Duration of rate limiting while accessing external IPAM API
======================================== ================================================================= ========== ========================================================

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
``pod``               Kubernetes pod name
``pod-short``         Deprecated, will be removed in Cilium 1.14 - use ``workload-name|pod`` instead. Short version of the Kubernetes pod name. Typically the deployment/replicaset name.
``dns``               All known DNS names of the source or destination (comma-separated)
``ip``                The IPv4 or IPv6 address
``reserved-identity`` Reserved identity label.
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

========================= ===============================================================================
Option Value              Description
========================= ===============================================================================
``source_ip``             The source IP of the flow.
``source_namespace``      The namespace of the pod if the flow source is from a Kubernetes pod.
``source_pod``            The pod name if the flow source is from a Kubernetes pod.
``source_workload``       The name of the source pod's workload (Deployment, Statefulset, Daemonset, ReplicationController, CronJob, Job, DeploymentConfig (OpenShift)).
``source_app``            The app name of the source pod, derived from pod labels (``app.kubernetes.io/name``, ``k8s-app``, or ``app``).
``destination_ip``        The destination IP of the flow.
``destination_namespace`` The namespace of the pod if the flow destination is from a Kubernetes pod.
``destination_pod``       The pod name if the flow destination is from a Kubernetes pod.
``destination_workload``  The name of the destination pod's workload (Deployment, Statefulset, Daemonset, ReplicationController, CronJob, Job, DeploymentConfig (OpenShift)).
``destination_app``       The app name of the source pod, derived from pod labels (``app.kubernetes.io/name``, ``k8s-app``, or ``app``).
``traffic_direction``     Identifies the traffic direction of the flow. Possible values are ``ingress``, ``egress`` and ``unknown``.
========================= ===============================================================================

When specifying the flow context, multiple values can be specified by separating them via the ``,`` symbol.
All labels listed are included in the metric, even if empty. For example, a metric configuration of
``http:labelsContext=source_namespace,source_pod`` will add the ``source_namespace`` and ``source_pod``
labels to all Hubble HTTP metrics.

.. _hubble_exported_metrics:

Exported Metrics
^^^^^^^^^^^^^^^^

Hubble metrics are exported under the ``hubble_`` Prometheus namespace.

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
