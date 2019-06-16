.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _metrics:

********************
Monitoring & Metrics
********************

``cilium-agent`` can be configured to serve `Prometheus <https://prometheus.io>`_
metrics. Prometheus is a pluggable metrics collection and storage system and
can act as a data source for `Grafana <https://grafana.com/>`_, a metrics
visualization frontend. Unlike some metrics collectors like statsd, Prometheus requires the
collectors to pull metrics from each source.

To expose any metrics, invoke ``cilium-agent`` with the
``--prometheus-serve-addr`` option. This option takes a ``IP:Port`` pair but
passing an empty IP (e.g. ``:9090``) will bind the server to all available
interfaces (there is usually only one in a container).

Exported Metrics
================

All metrics are exported under the ``cilium`` Prometheus namespace. When
running and collecting in Kubernetes they will be tagged with a pod name and
namespace.

Endpoint
--------

* ``endpoint_count``: Number of endpoints managed by this agent
* ``endpoint_regenerating``: Number of endpoints currently regenerating. Deprecated. Use endpoint_state with proper labels instead
* ``endpoint_regenerations``: Count of all endpoint regenerations that have completed, tagged by outcome
* ``endpoint_regeneration_time_stats_seconds``: Endpoint regeneration time stats labeled by scope.
* ``endpoint_state``: Count of all endpoints, tagged by different endpoint states

Build Queue
-----------

* ``buildqueue_entries``: Number of queued, waiting, and running builds.
    * ``state=running``: Number of builds currently in progress
    * ``state=blocked``: Number of builds selected for building, waiting for build conditions to be met.
    * ``state=waiting``: Number of builds in the queue, waiting to be selected.

Services
--------

* ``services_events_total``: Number of services events labeled by action type

Datapath
--------

* ``datapath_errors_total``: Total number of errors occurred in datapath
  management, labeled by area, name and address family.
* ``datapath_conntrack_gc_runs_total``: Number of times that the conntrack
  garbage collector process was run. It contains a label status that describes
  if it was successful or not.
* ``datapath_conntrack_gc_key_fallbacks_total``: Number of times that the Key fallback
  was invalid.
* ``datapath_conntrack_gc_entries``: The number of alive and deleted conntrack
  entries at the end of a garbage collector run labeled by datapath family.
* ``datapath_conntrack_gc_duration_seconds``: Duration in seconds of the garbage
  collector process labeled by datapath and completion status.

BPF
---

* ``bpf_syscall_duration_seconds``: Duration of BPF system call performed
  * Labels: ``operation={lookup, delete, update, objPin, getNextKey, ...}``, ``outcome={success|failure}``
* ``bpf_map_ops_total``: Number of BPF map operations performed
  * Labels: ``mapName=<string>``, ``operation={delete|update}``, ``outcome={success|failure}``

Drops/Forwards (L3/L4)
----------------------

* ``drop_count_total``: Total dropped packets, tagged by drop reason and ingress/egress direction
* ``drop_bytes_total``: Total dropped bytes, tagged by drop reason and ingress/egress direction
* ``forward_count_total``: Total forwarded packets, tagged by ingress/egress direction
* ``forward_bytes_total``: Total forwarded bytes, tagged by ingress/egress direction

Policy
------

* ``policy_count``: Number of policies currently loaded
* ``policy_regeneration_total``: Total number of policies regenerated successfully
* ``policy_regeneration_time_stats_seconds``: Policy regeneration time stats labeled by the scope.
* ``policy_max_revision``: Highest policy revision number in the agent
* ``policy_import_errors``: Number of times a policy import has failed
* ``policy_endpoint_enforcement_status``: Number of endpoints labeled by policy enforcement status.

Policy L7 (HTTP/Kafka)
----------------------

* ``proxy_redirects``: Number of redirects installed for endpoints, labeled by protocol
* ``proxy_upstream_reply_seconds``: Seconds waited for upstream server to reply to a request
* ``policy_l7_parse_errors_total``: Number of total L7 parse errors. Deprecated. Use ``policy_l7_total`` instead.
* ``policy_l7_forwarded_total``: Number of total L7 forwarded requests/responses. Deprecated. Use ``policy_l7_total`` instead.
* ``policy_l7_denied_total``: Number of total L7 denied requests/responses due to policy. Deprecated. Use ``policy_l7_total`` instead.
* ``policy_l7_received_total``: Number of total L7 received requests/responses. Deprecated. Use ``policy_l7_total`` instead.
* ``policy_l7_total``: Number of total L7 requests/responses, tagged by received/parse_errors/forwarded/denied

Identity
--------

* ``identity_count``: Number of identities currently allocated


Events external to Cilium
-------------------------
* ``event_ts``: Last timestamp when we received an event. Further labeled by
  source: ``api``, ``containerd``, ``k8s``.

Controllers
-----------

* ``controllers_runs_total``: Number of times that a controller process was run
  labeled by completion status
* ``controllers_runs_duration_seconds``: Duration in seconds of the controller
  process labeled by completion status

SubProcess
----------

* ``subprocess_start_total``: Number of times that Cilium has started a
  subprocess, labeled by subsystem

Kubernetes
-----------

* ``kubernetes_events_received_total``: Number of Kubernetes events received labeled by
  scope, action, validity and equality

* ``kubernetes_events_total``: Number of Kubernetes events processed labeled by
  scope, action and the execution result

* ``k8s_cnp_status_completion_seconds``: Duration in seconds in how long it
  took to complete a CNP status update labeled by number of attempts and
  outcome.

IPAM
------

* ``ipam_events_total``: Number of IPAM events received labeled by action and
  datapath family type

KVstore
-------

* ``kvstore_operations_duration_seconds``: Duration of kvstore operation

  * Labels: ``action``, ``kind``, ``outcome``, ``scope``

* ``kvstore_events_queue_seconds``: Duration of seconds of time received event was blocked before it could be queued

  * Labels: ``action``, ``scope``

Agent
-----

* ``agent_bootstrap_seconds``: Duration of various bootstrap phases
  * Labels: ``scope``, ``outcome``
* ``api_process_time_seconds``: Processing time of all the API calls made to the
  cilium-agent, labeled by API method, API path and returned HTTP code.

FQDN
-----

* ``fqdn_gc_deletions_total``: Number of FQDNs that have been cleaned on FQDN
  Garbage collector job


Cilium as a Kubernetes pod
==========================
The Cilium Prometheus reference configuration configures jobs that automatically
collect pod metrics marked with the appropriate two labels can be found
in :git-tree:`examples/kubernetes/addons/prometheus/templates/04-prometheus.yaml`

Your Cilium spec will need these annotations:

.. code-block:: yaml

        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"

The reference Cilium Kubernetes DaemonSet Kubernetes descriptor :git-tree:`examples/kubernetes/1.13/cilium.yaml`
is an example of how to configure ``cilium-agent`` and set the appropriate labels.

*Note: the port can be configured per-pod to any value and the label set
accordingly. Prometheus uses this label to discover the port.*

To configure automatic metric discovery and collection, Prometheus itself requires a
`kubernetes_sd_config configuration <https://prometheus.io/docs/prometheus/latest/configuration/configuration/>`_.
The configured rules are used to filter pods and nodes by label and annotation,
and tag the resulting metrics series. In the Kubernetes case Prometheus will
contact the Kubernetes API server for these lists and must have permissions to
do so.

An example of a Prometheus configuration can be found alongside the reference
Cilium Kubernetes DaemonSet spec in
:git-tree:`examples/kubernetes/addons/prometheus/templates/04-prometheus.yaml`

The critical discovery section is:

.. code-block:: yaml

      - job_name: 'kubernetes-pods'
        kubernetes_sd_configs:
          - role: pod
        relabel_configs:
          - source_labels: [__meta_kubernetes_pod_label_k8s_app]
            action: keep
            regex: cilium
          - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
            action: keep
            regex: true
          - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
            action: replace
            regex: (.+):(?:\d+);(\d+)
            replacement: ${1}:${2}
            target_label: __address__
          - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
            action: replace
            target_label: __metrics_path__
            regex: (.+)
          - action: labelmap
            regex: __meta_kubernetes_pod_label_(.+)
          - source_labels: [__meta_kubernetes_namespace]
            action: replace
            target_label: kubernetes_namespace
          - source_labels: [__meta_kubernetes_pod_name]
            action: replace
            target_label: kubernetes_pod_name

This job configures prometheus to do a number of things for all pods returned
by the Kubernetes API server:

- find and keep all pods that have labels ``k8s-app=cilium`` and ``prometheus.io/scrape=true``
- extract the IP and port of the pod from ``address`` and ``prometheus.io/port``
- discover the metrics URL path from the label ``prometheus.io/path`` or use the default of ``/metrics`` when it isn't present
- populate metrics tags for the Kubernetes namespace and pod name derived from the pod labels

Cilium as a host-agent on a node
================================
Prometheus can use a number of more common service discovery schemes, such as
consul and DNS, or a cloud provider API, such as AWS, GCE or Azure.
`Prometheus documentation <https://prometheus.io/docs/prometheus/latest/configuration/configuration/>`_
contains more information.

It is also possible to hard-code ``static-config`` sections that simply contain
a hardcoded IP address and port:

.. code-block:: yaml

      - job_name: 'cilium-agent-nodes'
        metrics_path: /metrics
        static_configs:
          - targets: ['192.168.33.11:9090']
            labels:
              node-id: i-0598c7d7d356eba47
              node-az: a
