# Deploying Prometheus & Grafana for Cilium

This is an example deployment that includes Prometheus and Grafana in a single
deployment.

The default installation contains:

- Grafana: A visualization dashboard with Cilium Dashboard pre-loaded.
- Prometheus: a time series database and monitoring system.

## Enable Metrics in Cilium & Cilium-operator

Enable prometheus metrics on all Cilium agents, be aware this will open the
port `9962` in all nodes of your cluster where a cilium-agent is running.

```
$ kubectl patch -n kube-system configmap cilium-config --type merge --patch '{"data":{"prometheus-serve-addr":":9962"}}'
configmap/cilium-config patched
```

Make sure you restart all Cilium agents so they can get the new ConfigMap with
`prometheus-serve-addr` option set.

Next, install all monitoring tools and configurations by running:

```
$ kubectl create -f examples/kubernetes/addons/prometheus/monitoring-example.yaml
namespace/monitoring created
configmap/prometheus created
deployment.apps/prometheus created
service/prometheus created
service/prometheus-open created
clusterrolebinding.rbac.authorization.k8s.io/prometheus created
clusterrole.rbac.authorization.k8s.io/prometheus created
serviceaccount/prometheus-k8s created
configmap/grafana-config created
deployment.apps/grafana created
service/grafana created
configmap/grafana-dashboards created
job.batch/grafana-dashboards-import created
```

## How to access Grafana

Expose the port on your local machine

```
kubectl -n cilium-monitoring port-forward service/grafana --address 0.0.0.0 --address :: 3000:3000
```

Access it via your browser: `https://localhost:3000`

## How to access Prometheus

Expose the port on your local machine

```
kubectl -n cilium-monitoring port-forward service/prometheus --address 0.0.0.0 --address :: 9090:9090
```

Access it via your browser: `https://localhost:9090`

## Dashboard Management Tools

This directory includes tools for managing Grafana dashboards within the monitoring example:

### Available Commands

```bash
# Show all available dashboard management commands
make dashboard-tools

# Extract dashboard JSON files from monitoring-example.yaml
make extract-dashboards

# Update Hubble dashboard with a new JSON file
make update-hubble HUBBLE_JSON=path/to/hubble-dashboard.json

# Run tests for the dashboard tools
make test-tools

# Set up the tools (make scripts executable)
make setup-tools
```

### Tools Directory

The `tools/` directory contains:

- **Dashboard management scripts**: Python utilities for extracting and updating dashboard configurations
- **Dashboard JSON files**: Generated or custom dashboard configurations
- **Makefile**: Comprehensive build system for dashboard operations
- **Tests**: Unit tests for the dashboard management utilities

For detailed usage of the dashboard tools, run:

```bash
make -C tools help
```
