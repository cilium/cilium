# Cilium resource churn testing

resource-churn is a reusable CL2 module to measure cilium performance under
kubernetes resource churn at scale. The configuration is primarily focused at
stressing a single node cilium components(cilium-agent, cilium-envoy) and
cluster component(cilium-operator) under dynamic and deterministic operations on
cluster.

## Setup

The module requires a minimum of 2 nodes kubernetes cluster with the below roles:

> For testing at scale, ensure cluster control plane is able to handle the load
> and is not the source of bottleneck. The local setup raises the apiserver and
> etcd limits in [test.sh](./test.sh), CI runs with a larger EKS control plane
> scaling tier.

### Scaffolding Node

A schedulable node in the cluster to run scaffolding components for the test.
The kwok controller, the kfuzz job and the CL2 prometheus stack all run here,
so nothing the test needs for itself competes with the node under test.
Configure the node with:

```bash
kubectl label node <infra-node> role.scaffolding/test-infra=true
export CL2_PROMETHEUS_NODE_SELECTOR='role.scaffolding/test-infra: "true"'
```

#### kwok

> https://github.com/fristonio/kwok/tree/dev/cilium

kwok manages the lifecycle of fake nodes for high scale testing without expensive
resources in the cluster. It marks the nodes Ready and runs the pod lifecycle
on them without a kubelet.

The fork adds Cilium specific node level lifecycle operations based on the current
cluster configuration. This includes managing CiliumNode, CiliumEndpoint and
CiliumIdentity objects with Node and Pod lifecycle. This is what makes node managed
resources visible to agent under test.

| Option | Description | Default |
| --- | --- | --- |
| `CL2_NUM_FAKE_NODES` | Number of fake nodes to create | `64` |
| `CL2_FAKE_NODES_READY_TIMEOUT` | How long to wait for the Readiness of fake nodes | `2m` |
| `CL2_KWOK_DOCKER_IMAGE` | kwok image, needs Cilium support implemented in the fork | `docker.io/fristonio/kwok:cilium` |
| `CL2_FAKE_NODE_IPAM_IGNORE` | Annotate fake nodes with `ipam.cilium.io/ignore`, keeping the operator IPAM away from them. Must be `false` for `cluster-pool`, where kwok needs the operator to populate the pod CIDRs of the fake node | `true` |
| `CL2_CILIUM_NAMESPACE` | Namespace cilium runs in. kwok, kfuzz and their RBAC are created here | `kube-system` |
| `CL2_CILIUM_CONFIGMAP_NAME` | ConfigMap kwok reads the Cilium configuration from | `cilium-config` |

The cluster needs the following before a run:

- **kwok CRDs and Stages**, which moves fake nodes and pods to their next state without
  the delays of a real kubelet.
- **The `kfuzz` namespace**, where kfuzz creates the resources it churns

```bash
kubectl apply -k "https://github.com/fristonio/kwok//kustomize/crd?ref=dev/cilium"
kubectl apply -k "https://github.com/fristonio/kwok//kustomize/stage/fast?ref=dev/cilium"

kubectl create namespace kfuzz
```

#### kfuzz

> https://github.com/fristonio/kfuzz

kfuzz churns the cilium control plane objects of the test. It runs once as a
job, churns for the test duration, deletes what it created and exits on its
own. The churn is started with a fixed known seed, so two runs of the same scenario
undergo similar churn, which is what makes multiple runs against different version
comparable.

| Option | Description | Default |
| --- | --- | --- |
| `CL2_TEST_SCENARIO` | Scenario to run, a file name in [scenarios](./scenarios) | `test-scenario` |
| `CL2_TEST_DURATION_SECONDS` | Duration to run kfuzz resource churn for | `900` |
| `CL2_KFUZZ_TICK_INTERVAL` | Interval between scenario template re-evaluation by kfuzz | `5s` |
| `CL2_KFUZZ_CLIENT_TUNING_SET` | Tuning set to use for apiserver request pacing | `qps` |
| `CL2_KFUZZ_CLIENT_QPS` | Request rate for apiserver operations | `256` |
| `CL2_KFUZZ_CLIENT_BURST_SIZE` | Burst size for apiserver requests | `512` |
| `CL2_KFUZZ_TERMINATION_GRACE_PERIOD_SECONDS` | Time kfuzz gets to clean up after the run | `900` |
| `CL2_KFUZZ_SKIP_RESOURCE_CLEANUP` | Leave the churned resources, the fake nodes and kwok in place, to inspect the cluster after a run | `false` |
| `CL2_KFUZZ_DOCKER_IMAGE` | kfuzz image | `docker.io/fristonio/kfuzz:cilium` |

### Test Node

Node under test. This is where node level components we are measuring runs.
The node hosts only test workloads and cluster daemonsets like `cilium-agent`,
`cilium-envoy`.

Before running the module, ensure that test node name config is set and the node
is cordoned so that only pods explicitly targetted using nodeName are
scheduled along with Daemonset pods.

```bash
export CL2_TEST_NODE_NAME=kind-worker
kubectl cordon ${CL2_TEST_NODE_NAME}
```

> For better cilium operator specific measurements its useful to target it at a
> seperate node.

## Test

Resource churn test is driven by `kfuzz` based on the configured scenario.
A [scenario](./scenarios/) is a probabilistic profile of the state of the resource
in cluster. The parameters of the scenario can be adjusted to reproduce the desired
type of user interaction with cluster at scale.

For example `global-identities-churn` scenario manages `4k-8k` remote endpoint
deployments(global identities), and on every tick has a `0.25` chance to add/delete
`16-128` of them, keeping the policy set small with slow churn.

## Measurements

The following measrurements are captured during the resource-churn window:

1. Cilium Agent metrics
2. Cilium Envoy metrics
3. Cilium Operator metrics
4. Cilium Agent pprofs (periodically with 60s duration)

## Local test setup

A local test setup can be created with kind using the included [helper script](./test.sh).

```bash
# Setup clusterloader
CL2_DIR=$(mktemp -d)
git clone https://github.com/kubernetes/perf-tests ${CL2_DIR}
pushd "${CL2_DIR}/clusterloader2"
git switch --detach d51da38a445d653c6f7cd039728d313cb31290b9 # ref pinned for CI.
go build -o ~/.local/bin cmd/clusterloader.go
popd
rm -rf ${CL2_DIR}

# Run a test scenario
TEST_SCENARIO=test-scenario ./test.sh

# Print the report as markdown.
ROOT_DIR=$(realpath ./../../../../)
go run ${ROOT_DIR}/tools/cl2-report -artifacts ./report
```

## Debug Monitoring

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

# Install grafana dashboard shipped with CL2 module to inspect and analyze
# the result of test runs.
kubectl create configmap --namespace monitoring \
  scale-test-dashboard --from-file=dashboard/cilium-scale.json
kubectl label --namespace monitoring configmap scale-test-dashboard grafana_dashboard="1"

kubectl -n monitoring rollout status deployment/grafana --timeout=90s

# USERNAME: admin
GRAFANA_PASSWORD=$(kubectl get secret --namespace monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo)
echo $GRAFANA_PASSWORD
kubectl --namespace monitoring port-forward svc/grafana 3000:80
```
