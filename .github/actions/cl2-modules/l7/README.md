# L7 Performance Testing

### Cluster Setup

Create cluster with 3 types of nodes and install cilium with envoy proxy enabled in Daemonset mode(enabled by default).

1. Server nodes
    * Label - `role.scaffolding/http-perf-server: true`
    * Since envoy runs as a daemonset in cilium installation, the scope of performance testing is per-node. This corresponds to server nodes in the test setup.
2. Client Nodes
    * Label - `role.scaffolding/http-perf-client: true`
    * These nodes run the load generator workloads(http client pods).
3. Monitoring Nodes
    * Label - `role.scaffolding/monitoring: true`
    * These nodes hosts the monitoring related components for clusterloader framework like prometheus, grafana etc.

### Test Phases

> The http performance testing workloads(client/server) uses [nighthawk](https://github.com/envoyproxy/nighthawk).

1. Deploy server instances.
    * Server instances are created as deployment where all replicas have affinity to the same node. This ensures that the service corresponding to this deployment always correlates to a single envoy instance.

2. **[Scenario 1]** Capture Baseline throughput and latency statistics of the setup.
    * Deploy http performance clients as jobs with configurable parallelism for each server instance.
    * Both client and server instances can be scaled independently to get the optimal basline statistics.

3. **[Scenario 2]** Deploy an empty L7 visibility policy(at server ingress) which puts envoy in the path of traffic and start client jobs(2)

4. **[Scenario 3]** Deploy L7 policy with HTTP allow rules(at server ingress) and capture performance test results(2).

### Test Validation

The following metrics are measured after the test run to assess the results:

* Policy Implmentation Delay
    * Given we don't stress policy engine in the suite, this is not highly relevent and is present as more of a sanity check.
* `cilium-agent` CPU and Memory usage
* `cilium-envoy` CPU and Memory usage
* Request processing latency for envoy(Downstream - Upstream)
* Relative impact on throughput(Baseline vs with L7 policy)
* Relative impact on P50 latency(Baseline vs with L7 policy)
* Client Request failures/Connection failures or timeout

## Running Locally

### Setup

```bash
ROOT_DIR=$(realpath ./../../../../)

# Kind cluster with 1 control plane and 3 worker nodes.
${ROOT_DIR}/contrib/scripts/kind.sh 1 3

kubectl label node kind-worker role.scaffolding/http-perf-server=true
kubectl label node kind-worker2 role.scaffolding/http-perf-client=true
kubectl label node kind-worker3 role.scaffolding/monitoring=true

# Install Cilium
cilium install \
    --wait \
    --chart-directory=${ROOT_DIR}/install/kubernetes/cilium \
    --helm-values=${ROOT_DIR}/contrib/testing/kind-common.yaml \
    --set=hubble.enabled=true \
    --set=pprof.enabled=true \
    --set prometheus.enabled=true \
    --set operator.prometheus.enabled=true \
    --set l7Proxy=true \
    --set envoyConfig.enabled=true
cilium status

# Setup Common Environment variables
export CL2_PROMETHEUS_PVC_ENABLED=false
export CL2_ENABLE_PVS=false

export CL2_PROMETHEUS_SCRAPE_CILIUM_OPERATOR=true
export CL2_PROMETHEUS_SCRAPE_CILIUM_AGENT=true
export CL2_PROMETHEUS_SCRAPE_CILIUM_AGENT_INTERVAL=5s

# Setup environment variables
export CL2_PIN_WORKLOADS_TO_LABELLED_NODES=true
export CL2_PROMETHEUS_NODE_SELECTOR='role.scaffolding/monitoring: "true"'

export CL2_NUM_TEST_NAMESPACES=1
export CL2_NUM_TEST_DEPLOYMENTS_PER_NAMESPACE=1
export CL2_NUM_POD_INSTANCES_PER_DEPLOYMENT=1
export CL2_NUM_CLIENT_INSTANCES_PER_DEPLOYMENT=1
export CL2_NUM_RULES_PER_NETWORK_POLICY=1000

# Nighthawk official images doesn't support arm64 builds yet.
export CL2_NIGHTHAWK_DOCKER_IMAGE="fristonio/nighthawk-dev:release-fristonio-test"
```

### Run Tests

```bash
clusterloader \
    -v=2 \
    --testconfig=config.yaml \
    --provider=kind \
    --enable-prometheus-server \
    --enable-pushgateway \
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
helm install grafana grafana/grafana --namespace monitoring \
    --set sidecar.dashboards.enabled=true \
    --set grafana.sidecar.dashboards.searchNamespace=ALL

# USERNAME: admin
GRAFANA_PASSWORD=$(kubectl get secret --namespace monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo)
echo $GRAFANA_PASSWORD
kubectl --namespace monitoring port-forward svc/grafana 3000:80
```