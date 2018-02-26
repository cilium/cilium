.. _metrics:

********************
Monitoring & Metrics
********************

cilium-agent can be configured to serve `Prometheus <https://prometheus.io>`_
metrics. Prometheus is a pluggable metrics collection and storage system and
can act as a data source for `Grafana <https://grafana.com/>`_, a metrics
visualisation system. Unlike some metrics collectors like statsd, Prometheus requires the
collectors to pull metrics from each source.

cilium must be invoked with the ``--prometheus-serve-addr`` option (the
`kubernetes example spec file <https://github.com/cilium/cilium/blob/master/examples/kubernetes/cilium.yaml>`_
already does this). This is a ``IP:Port`` pair and passing no IP (i.e.
``:9090``) will bind the server to all available interfaces (usually there is
only one in a container).


cilium as a kubernetes pod
==========================
The Prometheus reference configuration includes "jobs" to automatically collect pod metrics marked appropriately. Your cilium spec will need two labels:

.. code-block:: yaml

        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"

*Note: the port can be configured to any value. Prometheus uses this label to
discover the port.*

An example of how to do this can be found in the cilium
`kubernetes example spec file <https://github.com/cilium/cilium/blob/master/examples/kubernetes/cilium.yaml>`_

To configure this automatic discovery and collecction, Prometheus itself requires a
`kubernetes_sd_config <https://prometheus.io/docs/prometheus/latest/configuration/configuration/>`_
configuration.
This will use the kubernetes API server to discover pods, nodes etc. It also
takes rules that match and filter pods on labels and annotations, and otherwise
tag the metrics series.

An example `promethues configuration file <https://github.com/cilium/cilium/blob/master/examples/kubernetes/cilium.yaml>`_
can be found alongside the kubernetes cilium spec. The critical discovery section is:

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
by the kubernetes API server:

- find and keep all pods that have labels ``k8s-app=cilium`` and ``prometheus.io/scrape=true``
- extract the IP and port of the pod from ``address`` and ``prometheus.io/port``
- discover the metrics url path from the label ``prometheus.io/path`` and uses the default of ``/metrics`` when it isn't present
- populate metrics tags for the kubernetes namespace and pod name derived from the pod labels

cilium as a host-agent on a node
================================
Prometheus can use a number of more common service discovery schemes, such as
consul and DNS, or a cloud provider API, such as AWS EC2, GCE or Azure.
Relevant documentation can be found at the
`Prometheus site <https://prometheus.io/docs/prometheus/latest/configuration/configuration/>`_.

It is also possible to hard-code ``static-config`` sections that are simply an IP address and port:

.. code-block:: yaml

      - job_name: 'cilium-agent-nodes'
        metrics_path: /metrics
        static_configs:
          - targets: ['192.168.33.11:9090']
            labels:
              node-id: i-0598c7d7d356eba47
              node-az: a

Prometheus-operator Integration
===============================
To integrate with `Prometheus-operator <https://coreos.com/operators/prometheus/docs/latest/>`_, create a Service object (https://github.com/cilium/cilium/blob/master/examples/kubernetes/cilium-metrics-svc.yaml) and ServiceMonitor (https://github.com/cilium/cilium/blob/metrics/examples/kubernetes/prometheus-k8s-service-monitor-cilium.yaml).

.. parsed-literal::

   $ kubectl apply -f cilium-metrics-svc.yaml
   $ kubectl apply -f prometheus-k8s-service-monitor-cilium.yaml
