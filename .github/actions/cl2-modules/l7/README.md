# L7 Performance Testing

## Running Locally

### Setup

```bash
ROOT_DIR=$(realpath ./../../../../)

# Kind cluster with 1 control plane and 3 worker nodes.
${ROOT_DIR}/contrib/scripts/kind.sh 1 3

kubectl label node kind-worker2 role.scaffolding/http-perf-client=true
kubectl label node kind-worker3 role.scaffolding/http-perf-server=true

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
export CL2_PROMETHEUS_SCRAPE_CILIUM_OPERATOR=true
export CL2_PROMETHEUS_SCRAPE_CILIUM_AGENT=true
export CL2_PROMETHEUS_SCRAPE_CILIUM_AGENT_INTERVAL=5s

# Setup environment variables
export CL2_PIN_WORKLOADS_TO_LABELLED_NODES=true

export CL2_NUM_TEST_NAMESPACES=1
export CL2_NUM_TEST_DEPLOYMENTS_PER_NAMESPACE=1
export CL2_NUM_POD_INSTANCES_PER_DEPLOYMENT=3
export CL2_NUM_CLIENT_INSTANCES_PER_DEPLOYMENT=9
export CL2_NUM_RULES_PER_NETWORK_POLICY=1000
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