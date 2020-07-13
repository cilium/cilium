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
of the ``cilium-agent`` and ``cilium-operator`` processes. To run Cilium with
Prometheus metrics enabled, deploy it with the
``global.prometheus.enabled=true`` Helm value set.

Cilium metrics are exported under the ``cilium_`` Prometheus namespace.
When running and collecting in Kubernetes they will be tagged with a pod name
and namespace.

Installation
------------

You can enable metrics for ``cilium-agent`` with the Helm value
``global.prometheus.enabled=true``. To enable metrics for ``cilium-operator``,
use ``global.operatorPrometheus.enabled=true``.

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set global.prometheus.enabled=true \\
     --set global.operatorPrometheus.enabled=true

The ports can be configured via
``global.prometheus.port`` or ``global.operatorPrometheus.port`` respectively.

When metrics are enabled, all Cilium components will have the following
annotations. They can be used to signal Prometheus whether to scrape metrics:

.. code-block:: yaml

        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"

Prometheus will pick up the Cilium metrics automatically if the following
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
``global.hubble.enabled=true`` and provide a set of Hubble metrics you want to
enable via ``global.hubble.metrics.enabled``.

Some of the metrics can also be configured with additional options.
See the :ref:`Hubble exported metrics<hubble_exported_metrics>`
section for the full list of available metrics and their options.

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set global.hubble.enabled=true \\
     --set global.hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"

The port of the Hubble metrics can be configured with the
``global.hubble.metrics.port`` Helm value.

When deployed with a non-empty ``global.hubble.metrics.enabled`` Helm value, the
Cilium chart will create a Kubernetes headless service named ``hubble-metrics``
with the ``prometheus.io/scrape:'true'`` annotation set:

.. code-block:: yaml

        prometheus.io/scrape: "true"
        prometheus.io/port: "9091"

Set the following options in the ``scrape_configs`` section of Prometheus to
have it scrape all Hubble metrics from the endpoints automatically:

.. code-block:: yaml

    scrape_configs:
      - job_name: 'kubernetes-endpoints'
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

.. code:: bash

    kubectl -n cilium-monitoring port-forward service/grafana 3000:3000

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
``endpoint_count``                                                                              Number of endpoints managed by this agent
``endpoint_regenerations``                   ``outcome``                                        Count of all endpoint regenerations that have completed
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

Datapath
~~~~~~~~

============================================= ================================================== ========================================================
Name                                          Labels                                             Description
============================================= ================================================== ========================================================
``datapath_errors_total``                     ``area``, ``name``, ``family``                     Total number of errors occurred in datapath management
``datapath_conntrack_gc_runs_total``          ``status``                                         Number of times that the conntrack garbage collector process was run
``datapath_conntrack_gc_key_fallbacks_total``                                                    The number of alive and deleted conntrack entries at the end of a garbage collector run labeled by datapath family
``datapath_conntrack_gc_entries``             ``family``                                         The number of alive and deleted conntrack entries at the end of a garbage collector run
``datapath_conntrack_gc_duration_seconds``    ``status``                                         Duration in seconds of the garbage collector process
============================================= ================================================== ========================================================

BPF
~~~

========================================== ================================================== ========================================================
Name                                       Labels                                             Description
========================================== ================================================== ========================================================
``bpf_syscall_duration_seconds``           ``operation``, ``outcome``                         Duration of BPF system call performed
``bpf_map_ops_total``                      ``mapName``, ``operation``, ``outcome``            Number of BPF map operations performed
``bpf_maps_virtual_memory_max_bytes``                                                         Max memory used by BPF maps installed in the system
``bpf_progs_virtual_memory_max_bytes``                                                        Max memory used by BPF programs installed in the system
========================================== ================================================== ========================================================

Both ``bpf_maps_virtual_memory_max_bytes`` and ``bpf_progs_virtual_memory_max_bytes``
are currently reporting the system-wide memory usage of BPF that is directly
and not directly managed by Cilium. This might change in the future and only
report the BPF memory usage directly managed by Cilium.

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
``policy_count``                                                                              Number of policies currently loaded
``policy_regeneration_total``                                                                 Total number of policies regenerated successfully
``policy_regeneration_time_stats_seconds`` ``scope``                                          Policy regeneration time stats labeled by the scope
``policy_max_revision``                                                                       Highest policy revision number in the agent
``policy_import_errors``                                                                      Number of times a policy import has failed
``policy_endpoint_enforcement_status``                                                        Number of endpoints labeled by policy enforcement status
========================================== ================================================== ========================================================

Policy L7 (HTTP/Kafka)
~~~~~~~~~~~~~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``proxy_redirects``                      ``protocol``                                       Number of redirects installed for endpoints
``proxy_upstream_reply_seconds``                                                            Seconds waited for upstream server to reply to a request
``policy_l7_total``                      ``type``                                           Number of total L7 requests/responses
======================================== ================================================== ========================================================

Identity
~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``identity_count``                                                                          Number of identities currently allocated
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
``kubernetes_events_received_total``     ``scope``, ``action``, ``validity``, ``equiality`` Number of Kubernetes events received
``kubernetes_events_total``              ``scope``, ``action``, ``outcome``                 Number of Kubernetes events processed
``k8s_cnp_status_completion_seconds``    ``attempts``, ``outcome``                          Duration in seconds in how long it took to complete a CNP status update
======================================== ================================================== ========================================================

IPAM
~~~~

======================================== ============================================ ========================================================
Name                                     Labels                                       Description
======================================== ============================================ ========================================================
``ipam_events_total``                                                                 Number of IPAM events received labeled by action and datapath family type
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

cilium-operator
---------------

Configuration
^^^^^^^^^^^^^

``cilium-operator`` can be configured to serve metrics by running with the
option ``--enable-metrics``.  By default, the operator will expose metrics on
port 6942, the port can be changed with the option ``--metrics-address``.

Exported Metrics
^^^^^^^^^^^^^^^^

All metrics are exported under the ``cilium_operator_`` Prometheus namespace.

.. _ipam_metrics:

IPAM
~~~~

======================================== ================================ ========================================================
Name                                     Labels                           Description
======================================== ================================ ========================================================
``ipam_ips``                             ``type``                         Number of IPs allocated
``ipam_allocation_ops``                  ``subnetId``                     Number of IP allocation operations
``ipam_interface_creation_ops``          ``subnetId``, ``status``         Number of interfaces creation operations
``ipam_available``                                                        Number of interfaces with addresses available
``ipam_nodes_at_capacity``                                                Number of nodes unable to allocate more addresses
``ipam_resync_total``                                                     Number of synchronization operations with external IPAM API
``ipam_api_duration_seconds``            ``operation``, ``responseCode``  Duration of interactions with external IPAM API
``ipam_api_rate_limit_duration_seconds`` ``operation``                    Duration of rate limiting while accessing external IPAM API
======================================== ================================ ========================================================

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
will enable the the ``dns`` metric with the ``query`` and ``ignoreAAAA`` options,
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
============== ====================================================================================

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
``tcp_flags_total``              ``flag``, ``familiy``                    TCP flag occurrences
================================ ======================================== ==================================================

Options
"""""""

This metric supports :ref:`Context Options<hubble_context_options>`.
