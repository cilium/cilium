#!/usr/bin/env bash

# Archives the kubelet-rotated host logs (/var/log/pods) of the cilium-agent
# running on the given node. Unlike `kubectl logs`, these survive log rotation
# during a long churn run.
#
# Usage: collect-agent-host-logs.sh <node-name> <run-label> <output-archive>
#
# <run-label> only names the throw-away collector pod, so that consecutive
# collections in the same cluster don't collide.

set -euo pipefail

if [[ $# -ne 3 || -z "${1:-}" || -z "${2:-}" || -z "${3:-}" ]]; then
  echo "Usage: $0 <node-name> <run-label> <output-archive>" >&2
  exit 1
fi
NODE_NAME="$1"
RUN_LABEL="$2"
ARCHIVE="$3"

mapfile -t cilium_pods < <(
  kubectl get pods \
    --namespace kube-system \
    --selector k8s-app=cilium \
    --field-selector "spec.nodeName=${NODE_NAME}" \
    --output jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.uid}{"\n"}{end}'
)
if [ "${#cilium_pods[@]}" -ne 1 ]; then
  echo "Error: expected exactly one Cilium pod on node ${NODE_NAME}, found ${#cilium_pods[@]}" >&2
  exit 1
fi

IFS=$'\t' read -r CILIUM_POD CILIUM_POD_UID <<< "${cilium_pods[0]}"
if [ -z "${CILIUM_POD}" ]; then
  echo "Error: Cilium pod name is empty for node ${NODE_NAME}" >&2
  exit 1
fi
if [ -z "${CILIUM_POD_UID}" ]; then
  echo "Error: Cilium pod UID is empty for pod ${CILIUM_POD}" >&2
  exit 1
fi

COLLECTOR_POD="cilium-agent-host-log-collector-${RUN_LABEL}"
kubectl delete pod "${COLLECTOR_POD}" --namespace kube-system --ignore-not-found --wait=true || true
cleanup() {
  kubectl delete pod "${COLLECTOR_POD}" --namespace kube-system --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${COLLECTOR_POD}
  namespace: kube-system
spec:
  nodeName: ${NODE_NAME}
  hostNetwork: true
  tolerations:
    - operator: Exists
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
    - name: collector
      image: docker.io/library/busybox:1.37.0
      command: ["sh", "-c", "sleep 300"]
      securityContext:
        privileged: true
        runAsUser: 0
        runAsNonRoot: false
      volumeMounts:
        - name: host-logs
          mountPath: /host-logs
          readOnly: true
  volumes:
    - name: host-logs
      hostPath:
        path: /var/log/pods
        type: Directory
EOF

kubectl wait pod "${COLLECTOR_POD}" \
  --namespace kube-system \
  --for=condition=Ready \
  --timeout=2m

HOST_LOG_DIR="kube-system_${CILIUM_POD}_${CILIUM_POD_UID}/cilium-agent"
if ! kubectl exec --namespace kube-system "${COLLECTOR_POD}" -- test -d "/host-logs/${HOST_LOG_DIR}"; then
  echo "Error: Cilium agent host log directory /var/log/pods/${HOST_LOG_DIR} does not exist" >&2
  exit 1
fi

mkdir -p "$(dirname "${ARCHIVE}")"
kubectl exec --namespace kube-system "${COLLECTOR_POD}" -- \
  tar -C /host-logs -czf - "${HOST_LOG_DIR}" > "${ARCHIVE}"
chmod a+r "${ARCHIVE}"
tar -tzf "${ARCHIVE}"
