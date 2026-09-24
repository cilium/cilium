#!/usr/bin/env bash

ROOT_DIR=$(realpath ./../../../../)

# Kind cluster with 1 control plane and 2 worker nodes.
${ROOT_DIR}/contrib/scripts/kind.sh 1 2
make -C "${ROOT_DIR}" kind-image

kubectl label node kind-worker2 role.scaffolding/test-infra=true
kubectl label node kind-worker role.scaffolding/test-node=true

# Cordon the test node so only pods explicitly targetted using nodeName
# are scheduled along with Daemonset pods.
kubectl cordon kind-worker
kubectl create namespace kfuzz

# Add kwok node anti affinity so that kube-proxy is not scheduled on these nodes.
if kubectl -n kube-system get daemonset kube-proxy &> /dev/null; then
  kubectl -n kube-system patch daemonset kube-proxy --type=json \
	-p='[
	  {"op": "add", "path": "/spec/template/spec/affinity", "value": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "type", "operator": "NotIn", "values": ["kwok"]}]}]}}}}
	]'
fi

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
export CL2_TEST_DURATION=20m

export CL2_NUM_FAKE_NODES=128

export CL2_KFUZZ_CLIENT_QPS=128
export CL2_KFUZZ_TERMINATION_GRACE_PERIOD_SECONDS=900
export CL2_KFUZZ_SKIP_RESOURCE_CLEANUP=false

cat <<EOF > /tmp/policy-churn-test-values.yaml
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

cilium install --wait \
    --chart-directory=${ROOT_DIR}/install/kubernetes/cilium \
    --helm-values=${ROOT_DIR}/contrib/testing/kind-values.yaml \
    --helm-values=/tmp/policy-churn-test-values.yaml
cilium status --wait

for file in ./scenarios/*.yaml; do
    scenario=$(basename "${file}")
    export CL2_TEST_SCENARIO="${scenario%.*}"

    clusterloader \
        -v=2 \
        --testconfig=config.yaml \
        --provider=kind \
        --enable-prometheus-server \
        --report-dir=./report \
        --prometheus-scrape-kube-proxy=false \
        --prometheus-scrape-kubelets=true \
        --prometheus-apiserver-scrape-port=6443 \
        --kubeconfig=${HOME}/.kube/config \
        --tear-down-prometheus-server=false \
        --experimental-prometheus-snapshot-to-report-dir=true \
        --prometheus-additional-monitors-path=monitors


    echo "[*] Cleaning up any orphaned resources"

    kubectl --namespace kfuzz delete deployments --all
    kubectl --namespace kfuzz delete ciliumnetworkpolicies --all
    kubectl --namespace kfuzz delete ciliumcidrgroups --all

    kubectl delete namespace kfuzz --wait
    kubectl delete nodes -l type=kwok

    kubectl -n kube-system delete deployments kwok-controller-deployment-0 kfuzz-deployment-0 || true

    kubectl delete ciliumidentities -l cilium.io/owner=kwok

    sleep 150
done
