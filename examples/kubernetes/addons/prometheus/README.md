# Prometheus Cilium Example

This is an example deployment that includes Prometheus, Kube-metrics and
Grafana in a single deployment.

The default installation contains:

- Kube-metrics: a metrics system to export Kubernetes data to Prometheus.
- Grafana: A visualization dashboard with Cilium Dashboard pre-loaded.
- Prometheus: a time series database and monitoring system.

## Installation

```
$ kubectl create -f examples/kubernetes/addons/prometheus/monitoring-example.yaml
configmap/cilium-metrics-config created
namespace/monitoring created
clusterrolebinding.rbac.authorization.k8s.io/kube-state-metrics created
clusterrole.rbac.authorization.k8s.io/kube-state-metrics created
deployment.apps/kube-state-metrics created
rolebinding.rbac.authorization.k8s.io/kube-state-metrics created
role.rbac.authorization.k8s.io/kube-state-metrics-resizer created
serviceaccount/kube-state-metrics created
service/kube-state-metrics created
configmap/prometheus created
deployment.extensions/prometheus created
service/prometheus created
service/prometheus-open created
clusterrolebinding.rbac.authorization.k8s.io/prometheus created
clusterrole.rbac.authorization.k8s.io/prometheus created
serviceaccount/prometheus-k8s created
configmap/grafana-config created
deployment.extensions/grafana created
service/grafana created
configmap/grafana-dashboards created
job.batch/grafana-dashboards-import created
```

## How to access:

Prometheus and Grafana are available to access from outside cluster on different
ports:

Grafana: <anyNodeIP>:31000
Prometheus: <anyNodeIP>:31001
