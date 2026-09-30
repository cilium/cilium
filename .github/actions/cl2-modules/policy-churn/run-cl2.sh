#!/usr/bin/env bash

# Runs the policy-churn CL2 module once against the current kubeconfig context.
#
# Must be invoked from the clusterloader2 directory of a perf-tests checkout
# that has add-prometheus-host-override-env-var.patch applied, with the Cilium
# release under test already installed.
#
# Configuration (in addition to the CL2_* env vars read by config.yaml):
#   REPORT_DIR       directory (relative to CWD) for the CL2 report, created if
#                    missing. Use a distinct directory per run.
#   CL2_OUTPUT_FILE  file (relative to CWD) to tee the CL2 log to.
#   MODULE_DIR       path to the policy-churn module directory.

set -euo pipefail

REPORT_DIR="${REPORT_DIR:-./report}"
CL2_OUTPUT_FILE="${CL2_OUTPUT_FILE:-cl2-output.txt}"
MODULE_DIR="${MODULE_DIR:-../../.github/actions/cl2-modules/policy-churn}"

echo "CL2-related environment variables"
printenv | grep CL2_ || true

cat <<EOF > ./cl2-test-overrides.yaml
PROMETHEUS_SCRAPE_APISERVER_ONLY: true
EOF

mkdir -p "${REPORT_DIR}"

# CL2 reaches its in-cluster Prometheus over this port-forward instead of the
# apiserver's services/proxy subresource, which EKS refuses to proxy to
# cluster-pool pod IPs outside the VPC CIDR. Supervised in a loop, since a
# single port-forward rarely survives a whole churn run.
(
  waited=0
  until kubectl get svc -n monitoring prometheus-k8s &> /dev/null; do
    if [ "${waited}" -ge 300 ]; then
      echo "$(date -Is) [prometheus-port-forward] prometheus-k8s Service still doesn't exist after 300s, giving up. CL2 likely failed before/while standing up its own Prometheus stack -- check the 'go run' output above/below, not this port-forward."
      kubectl get pods -n monitoring -o wide || true
      kubectl get events -n monitoring --sort-by=.lastTimestamp || true
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "$(date -Is) [prometheus-port-forward] prometheus-k8s Service found after ${waited}s"
  kubectl get pods -n monitoring -o wide || true
  while true; do
    echo "$(date -Is) [prometheus-port-forward] (re)connecting"
    kubectl port-forward -n monitoring svc/prometheus-k8s 9090:9090 &
    KUBECTL_PID=$!
    for _ in $(seq 1 10); do
      if curl -sf "http://localhost:9090/-/ready" &> /dev/null; then
        echo "$(date -Is) [prometheus-port-forward] confirmed reachable at http://localhost:9090"
        break
      fi
      sleep 2
    done
    wait "${KUBECTL_PID}" || true
    echo "$(date -Is) [prometheus-port-forward] port-forward exited, reconnecting in 2s"
    sleep 2
  done
) &
PF_PID=$!
trap 'kill "${PF_PID}" 2>/dev/null || true; pkill -f "kubectl port-forward -n monitoring svc/prometheus-k8s" 2>/dev/null || true' EXIT

export PROMETHEUS_HOST_OVERRIDE="localhost:9090"
echo "PROMETHEUS_HOST_OVERRIDE=${PROMETHEUS_HOST_OVERRIDE}"

go run ./cmd/clusterloader.go \
  -v=2 \
  --testconfig="${MODULE_DIR}/config.yaml" \
  --prometheus-additional-monitors-path="${MODULE_DIR}/monitors" \
  --provider=aws \
  --enable-exec-service=false \
  --enable-prometheus-server \
  --report-dir="${REPORT_DIR}" \
  --prometheus-scrape-kube-proxy=false \
  --prometheus-scrape-kubelets=false \
  --kubeconfig="$HOME/.kube/config" \
  --tear-down-prometheus-server=false \
  --experimental-prometheus-snapshot-to-report-dir=true \
  --testoverrides=./cl2-test-overrides.yaml \
  2>&1 | tee "${CL2_OUTPUT_FILE}"

# The cilium-cli creates files owned by the root user when run as a container.
sudo chmod --recursive +r "${REPORT_DIR}"
