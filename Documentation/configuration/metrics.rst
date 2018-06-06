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
* ``endpoint_regenerating``: Number of endpoints currently regenerating
* ``endpoint_regenerations``: Count of all endpoint regenerations that have completed, tagged by outcome
* ``endpoint_state``: Count of all endpoints, tagged by different endpoint states

Datapath
--------

* ``datapath_errors_total``: Total number of errors occurred in datapath management, labeled by area, name and address family.

Drops/Forwards (L3/L4)
----------------------

* ``drop_count_total``: Total dropped packets, tagged by drop reason and ingress/egress direction
* ``forward_count_total``: Total forwarded packets, tagged by ingress/egress direction

Policy Imports
--------------

* ``policy_count``: Number of policies currently loaded
* ``policy_max_revision``: Highest policy revision number in the agent
* ``policy_import_errors``: Number of times a policy import has failed

Policy L7 (HTTP/Kafka)
----------------------

* ``policy_l7_parse_errors_total``: Number of total L7 parse errors
* ``policy_l7_forwarded_total``: Number of total L7 forwarded requests/responses
* ``policy_l7_denied_total``: Number of total L7 denied requests/responses due to policy
* ``policy_l7_received_total``: Number of total L7 received requests/responses

Events external to Cilium
-------------------------
* ``event_ts``: Last timestamp when we received an event. Further labeled by
  source: ``api``, ``containerd``, ``k8s``.

Cilium as a Kubernetes pod
==========================
The Cilium `Prometheus reference configuration <https://github.com/cilium/cilium/blob/master/examples/kubernetes/prometheus.yaml>`_
configures jobs that automatically collect pod metrics marked with the
appropriate two labels.

Your Cilium spec will need these annotations:

.. code-block:: yaml

        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"

The reference Cilium Kubernetes DaemonSet `Kubernetes spec <https://github.com/cilium/cilium/blob/master/examples/kubernetes/cilium.yaml>`_
is an example of how to configure ``cilium-agent`` and set the appropriate labels.

*Note: the port can be configured per-pod to any value and the label set
accordingly. Prometheus uses this label to discover the port.*

To configure automatic metric discovery and collection, Prometheus itself requires a
`kubernetes_sd_config configuration <https://prometheus.io/docs/prometheus/latest/configuration/configuration/>`_.
The configured rules are used to filter pods and nodes by label and annotation,
and tag the resulting metrics series. In the Kubernetes case Prometheus will
contact the Kubernetes API server for these lists and must have permissions to
do so.

An example `promethues configuration <https://github.com/cilium/cilium/blob/master/examples/kubernetes/prometheus.yaml>`_
can be found alongside the reference Cilium Kubernetes DaemonSet spec.

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
