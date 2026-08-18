# Policy churn scale testing

## Cluster Setup

Create cluster with 3 node roles:

1. **Control plane** - Runs cluster-operations components not relevant to this test (eg. coredns).
2. **Test infra node** - `role.scaffolding/test-infra: "true"`
    - Hosts kwok, kfuzz, and the monitoring stack (prometheus etc).
3. **Test node** - `role.scaffolding/test-node: "true"`
    - CL2 module expects the node name to be populated in `CL2_TEST_NODE_NAME`

## Test Setup

### Test Parameters

| Variable                                     | Default                  | Description                                                                                                                         |
| -------------------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `CL2_TEST_NODE_NAME`                         | _(required)_             | Name of the node under test.                                                                                                        |
| `CL2_TEST_SCENARIO`                          | `policy-selectors-churn` | Test scenario to run: `scenarios/<name>.yaml`                                                                                       |
| `CL2_KWOK_DOCKER_IMAGE`                      | `fristonio/kwok:latest`  |                                                                                                                                     |
| `CL2_NUM_FAKE_NODES`                         | `64`                     | Number of fake Nodes for testing.                                                                                                   |
| `CL2_CILIUM_NAMESPACE`                       | `kube-system`            | Namespace Cilium is running in.                                                                                                     |
| `CL2_CILIUM_CONFIGMAP_NAME`                  | `cilium-config`          | Name of Cilium's ConfigMap(read by kwok at startup).                                                                                |
| `CL2_FAKE_NODES_READY_TIMEOUT`               | `1m`                     | Timeout waiting for all fake nodes to go Ready.                                                                                     |
| `CL2_KFUZZ_DOCKER_IMAGE`                     | `fristonio/kfuzz:latest` |                                                                                                                                     |
| `CL2_TEST_DURATION`                          | `15m`                    | How long kfuzz churns before the test stops it.                                                                                     |
| `CL2_KFUZZ_TICK_INTERVAL`                    | `5s`                     | kfuzz `--tick-interval`.                                                                                                            |
| `CL2_KFUZZ_CLIENT_TUNING_SET`                | `qps`                    | kfuzz `--client-tuning-set` (`qps`\|`randomized`\|`stepped`).                                                                       |
| `CL2_KFUZZ_CLIENT_QPS`                       | `64`                     | kfuzz `--client-qps`.                                                                                                               |
| `CL2_KFUZZ_CLIENT_BURST_SIZE`                | `128`                    | kfuzz `--client-burst-size`.                                                                                                        |
| `CL2_KFUZZ_CLIENT_STEP_DELAY`                | `1s`                     | kfuzz `--client-step-delay` (only used by the `stepped` tuning set).                                                                |
| `CL2_KFUZZ_TERMINATION_GRACE_PERIOD_SECONDS` | `600`                    | Pod-level grace period for kfuzz's cleanup-on-delete hook; Time to wait for the pod to actually terminate before deleting its RBAC. |
| `CL2_ENABLE_VIOLATIONS`                      | `false`                  | Whether threshold breaches in `metrics.yaml` fail the test.                                                                         |

### Test Validation

Test validation is done using metrics measurements. The following metrics are measured:

| Metric                                             | Threshold          | Description                                                            |
| -------------------------------------------------- | ------------------ | ---------------------------------------------------------------------- |
| `cilium_policy_implementation_delay_bucket`        | P90 < 5s, P50 < 1s | Latency between receiving a policy update and its datapth plumbing     |
| `cilium_policy_incremental_update_duration_bucket` | P90 < 5s, P50 < 1s | Latency between receiving an identity update and its datapath plumbing |

## Running Locally

### Setup

```bash
ROOT_DIR=$(realpath ./../../../../)

# Kind cluster with 1 control plane and 2 worker nodes.
${ROOT_DIR}/contrib/scripts/kind.sh 1 2

kubectl label node kind-worker2 role.scaffolding/test-infra=true
kubectl label node kind-worker role.scaffolding/test-node=true

# Cordon the test node so only pods explicitly targetted using nodeName
# are scheduled along with Daemonset pods.
kubectl cordon kind-worker
kubectl create namespace kfuzz

cat <<EOF > /tmp/policy-churn-test-values.yaml
debug:
  enabled: true
pprof:
  enabled: true

prometheus:
  enabled: true
operator:
  prometheus:
    enabled: true

healthChecking: false
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
      - matchExpressions:
        - key: type
          operator: NotIn
          values:
          - kwok
envoy:
  enabled: true
  debug:
    enabled: true
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: type
            operator: NotIn
            values:
            - kwok
EOF

# Install Cilium and wait for readiness.
cilium install --wait \
    --chart-directory=${ROOT_DIR}/install/kubernetes/cilium \
    --helm-values=/tmp/policy-churn-test-values.yaml
cilium status --wait

# Ensure kwok CRDs and Stages are configured
kubectl apply -k "https://github.com/kubernetes-sigs/kwok/kustomize/crd?ref=v0.8.0"
kubectl apply -k "https://github.com/kubernetes-sigs/kwok/kustomize/stage/fast?ref=v0.8.0"

# Setup CL2 Common Environment variables
export CL2_ENABLE_PVS=false
export CL2_PROMETHEUS_PVC_ENABLED=false
export CL2_PROMETHEUS_NODE_SELECTOR='role.scaffolding/test-infra: "true"'

# Disable cilium-agent metrics scraping. We need node label on metrics so the monitor
# is managed separately.
export CL2_PROMETHEUS_SCRAPE_CILIUM_OPERATOR=true
export CL2_PROMETHEUS_SCRAPE_CILIUM_AGENT=false

export CL2_TEST_NODE_NAME=kind-worker
export CL2_TEST_DURATION=15m
export CL2_TEST_SCENARIO=global-identities-churn
```

> NOTE: Add node affinity for kube-proxy if required

```bash
kubectl -n kube-system patch daemonset kube-proxy --type=json \
  -p='[
    {"op": "add", "path": "/spec/template/spec/affinity", "value": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "type", "operator": "NotIn", "values": ["kwok"]}]}]}}}}
]'
```

### Run Tests

Clone and build clusterloader2 if not already:

```bash
git clone https://github.com:kubernetes/perf-tests.git /tmp/perf-tests
go build -C /tmp/perf-tests/clusterloader2/ ./cmd/clusterloader.go -o ~/.local/bin/
```

```bash
clusterloader \
    -v=2 \
    --testconfig=config.yaml \
    --provider=kind \
    --enable-prometheus-server \
    --report-dir=./report \
    --prometheus-scrape-kube-proxy=false \
    --prometheus-scrape-kubelets=true \
    --prometheus-apiserver-scrape-port=6443 \
    --kubeconfig=$HOME/.kube/config \
    --tear-down-prometheus-server=false \
    --experimental-prometheus-snapshot-to-report-dir=true \
    --prometheus-additional-monitors-path=monitors
```

### Debug Monitoring

> By default Clusterloader runs with a very old version of grafana.
> Most of the dashboards don't work with this grafana version.

```bash
# Setup grafana
kubectl -n monitoring delete deployment/grafana service/grafana serviceaccount/grafana

helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

cat <<EOF | helm install grafana grafana/grafana --namespace monitoring -f -
sidecar:
  dashboards:
    enabled: true
grafana:
  sidecar:
    dashboards:
      searchNamespace: ALL
datasources:
  datasources.yaml:
    apiVersion: 1
    datasources:
    - name: prometheus
      type: prometheus
      access: proxy
      url: http://prometheus-k8s:9090
      isDefault: true
EOF

kubectl create configmap --namespace monitoring \
  scale-test-dashboard --from-file=dashboard/cilium-scale.json
kubectl label --namespace monitoring configmap scale-test-dashboard grafana_dashboard="1"

# USERNAME: admin
GRAFANA_PASSWORD=$(kubectl get secret --namespace monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo)
echo $GRAFANA_PASSWORD
kubectl --namespace monitoring port-forward svc/grafana 3000:80
```
