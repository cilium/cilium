#!/usr/bin/env bash

ROOT_DIR=$(realpath ./../../../../)

export EXTRA_KUBEADM_CONFIG_PATCH='
kind: ClusterConfiguration
etcd:
  local:
    extraArgs:
      quota-backend-bytes: "4294967296"
apiServer:
  extraArgs:
    max-requests-inflight: "1200"
    max-mutating-requests-inflight: "600"
    http2-max-streams-per-connection: "1000"
    etcd-compaction-interval: "2m"
controllerManager:
  extraArgs:
    kube-api-qps: "100"
    kube-api-burst: "200"
scheduler:
  extraArgs:
    kube-api-qps: "100"
    kube-api-burst: "200"
'

${ROOT_DIR}/contrib/scripts/kind.sh 1 1
make -C "${ROOT_DIR}" kind-image

kubectl taint nodes --all node-role.kubernetes.io/control-plane- 2>/dev/null
kubectl taint nodes --all node-role.kubernetes.io/master- 2>/dev/null

kubectl label node kind-control-plane role.scaffolding/test-infra=true
kubectl label node kind-worker role.scaffolding/test-node=true

# Cordon the test node so only pods explicitly targetted using nodeName
# are scheduled along with Daemonset pods.
kubectl cordon kind-worker
kubectl create namespace kfuzz

# Create kwok CRDs and Stages
kubectl apply -k "https://github.com/fristonio/kwok//kustomize/crd?ref=dev/cilium"
kubectl apply -k "https://github.com/fristonio/kwok//kustomize/stage/fast?ref=dev/cilium"

# Add kwok node anti affinity so that kube-proxy is not scheduled on fake nodes.
if kubectl -n kube-system get daemonset kube-proxy &> /dev/null; then
  kubectl -n kube-system patch daemonset kube-proxy --type=json \
	-p='[
	  {"op": "add", "path": "/spec/template/spec/affinity", "value": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "type", "operator": "NotIn", "values": ["kwok"]}]}]}}}}
	]'
fi

# Setup CL2 Common Environment variables
export CL2_ENABLE_PVS=false
export CL2_PROMETHEUS_PVC_ENABLED=false
export CL2_PROMETHEUS_NODE_SELECTOR='role.scaffolding/test-infra: "true"'

# Disable cilium-agent metrics scraping. We need node label on metrics so the monitor
# is managed separately.
export CL2_PROMETHEUS_SCRAPE_CILIUM_OPERATOR=true
export CL2_PROMETHEUS_SCRAPE_CILIUM_AGENT=false

export CL2_TEST_NODE_NAME=kind-worker
export CL2_TEST_DURATION_SECONDS=300
export CL2_NUM_FAKE_NODES=16

export CL2_KFUZZ_TERMINATION_GRACE_PERIOD_SECONDS=150
export CL2_KFUZZ_SKIP_RESOURCE_CLEANUP=false

CILIUM_INSTALL_VALUES=$(mktemp)
cat <<EOF > "${CILIUM_INSTALL_VALUES}"
debug:
  enabled: false
pprof:
  enabled: true

prometheus:
  enabled: true
operator:
  prometheus:
    enabled: true

bpf:
  policyMapMax: 65536

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
    enabled: false
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

cilium install \
	--chart-directory="${ROOT_DIR}/install/kubernetes/cilium" \
	--helm-values="${ROOT_DIR}/contrib/testing/kind-values.yaml" \
	--values "${CILIUM_INSTALL_VALUES}"
cilium status --wait

# Set TEST_SCENARIO to run just that one scenario, eg
TEST_SCENARIO="${TEST_SCENARIO:-}"

for file in ./scenarios/*.yaml; do
    scenario=$(basename "${file}")
    export CL2_TEST_SCENARIO="${scenario%.*}"

	if [[ -n "${TEST_SCENARIO}" && "${CL2_TEST_SCENARIO}" != "${TEST_SCENARIO}" ]]; then
        continue
    fi

    clusterloader \
        -v=2 \
        --testconfig=config.yaml \
        --provider=kind \
        --enable-prometheus-server \
        --prometheus-memory-request=2Gi \
        --report-dir=./report/${CL2_TEST_SCENARIO} \
        --prometheus-scrape-kube-proxy=false \
        --prometheus-scrape-kubelets=true \
        --prometheus-apiserver-scrape-port=6443 \
        --kubeconfig=${HOME}/.kube/config \
        --tear-down-prometheus-server=false \
        --experimental-prometheus-snapshot-to-report-dir=true \
        --prometheus-additional-monitors-path=monitors

    echo "[*] Cleaning up any orphaned resources"

    kubectl delete ciliumcidrgroups --all
    kubectl --namespace kfuzz delete deployments --all
    kubectl --namespace kfuzz delete ciliumnetworkpolicies --all

    kubectl delete namespace kfuzz --wait
    kubectl delete nodes -l type=kwok

    kubectl -n kube-system delete job kfuzz-0 || true
    kubectl -n kube-system delete pod kwok-0 || true

    kubectl delete ciliumidentities -l io.kubernetes.pod.namespace=kfuzz

    sleep 90
done
