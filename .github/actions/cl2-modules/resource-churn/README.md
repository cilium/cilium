# Cilium resource churn testing

### Local test setup

A local test setup can be created with kind using the included [helper script](./test.sh).

```bash
# Run a test scenario
TEST_SCENARIO=test-scenario ./test.sh

# Print the report as markdown.
ROOT_DIR=$(realpath ./../../../../)
go run ${ROOT_DIR}/tools/cl2-report -artifacts ./report
```

### Debug Monitoring

> By default Clusterloader runs with a very old version of grafana.
> Most of the dashboards don't work with this grafana version.

```bash
# Setup grafana
kubectl -n monitoring delete deployment/grafana service/grafana serviceaccount/grafana || true

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

kubectl -n monitoring rollout status deployment/grafana --timeout=90s

# USERNAME: admin
GRAFANA_PASSWORD=$(kubectl get secret --namespace monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo)
echo $GRAFANA_PASSWORD
kubectl --namespace monitoring port-forward svc/grafana 3000:80
```
