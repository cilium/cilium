#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || -z "${1:-}" ]]; then
  echo "Usage: $0 <node-name>" >&2
  exit 1
fi
NODE_NAME="$1"

# Last 2 Hour
DASHBOARD_TO_MS="${DASHBOARD_TO_MS:-$(date +%s%3N)}"
DASHBOARD_FROM_MS="${DASHBOARD_FROM_MS:-$((DASHBOARD_TO_MS - 7200000))}"

DASHBOARD_UID="adzhr7t"
DASHBOARD_SLUG="cilium-scale-test"
OUTPUT_PATH="${OUTPUT_PATH:-./report/cilium-scale-dashboard.png}"

MAGICK_CMD=""
if command -v magick &> /dev/null; then
  MAGICK_CMD="magick"
elif command -v convert &> /dev/null; then
  MAGICK_CMD="convert"
else
  echo "ImageMagick (magick/convert) is required to crop the render to its actual content height. Install it and re-run." >&2
  exit 1
fi

echo "[*] Provisioning the dashboard via the grafana sidecar"

# Remove the old grafana instance laying around from CL2 run.
kubectl -n monitoring delete deployment/grafana service/grafana serviceaccount/grafana || true
kubectl create configmap scale-test-dashboard \
  --namespace monitoring \
  --from-file=cilium-scale.json=./dashboard/cilium-scale.json \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl label configmap scale-test-dashboard -n monitoring grafana_dashboard=1 --overwrite

echo "[*] Installing grafana + grafana-image-renderer via helm"

helm repo add grafana-community https://grafana-community.github.io/helm-charts --force-update
cat <<EOF | helm upgrade --install grafana grafana-community/grafana --namespace monitoring --wait --timeout=5m -f -
image:
  tag: "13.2.1"

sidecar:
  dashboards:
    enabled: true
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

imageRenderer:
  enabled: true
  image:
    tag: "v5.12.3"
  env:
    BROWSER_MAX_WIDTH: "2500"
    BROWSER_MAX_HEIGHT: "7500"

grafana.ini:
  auth.anonymous:
    enabled: true
    org_role: Viewer
EOF

echo "[*] Rendering the dashboard for node ${NODE_NAME} to ${OUTPUT_PATH}"
GRAFANA_PW=$(kubectl get secret --namespace monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode)

kubectl --namespace monitoring port-forward svc/grafana 13000:80 &
PF_PID=$!
trap 'kill "${PF_PID}" 2>/dev/null || true' EXIT

for _ in $(seq 1 15); do
  curl -sf http://localhost:13000/api/health &> /dev/null && break
  sleep 2
done

RAW_SCREENSHOT="$(mktemp --suffix=.png)"
curl -sfG -u "admin:${GRAFANA_PW}" \
  "http://localhost:13000/render/d/${DASHBOARD_UID}/${DASHBOARD_SLUG}" \
  --data-urlencode "orgId=1" \
  --data-urlencode "from=${DASHBOARD_FROM_MS}" \
  --data-urlencode "to=${DASHBOARD_TO_MS}" \
  --data-urlencode "width=2500" \
  --data-urlencode "height=7500" \
  --data-urlencode "tz=UTC" \
  --data-urlencode "var-node=${NODE_NAME}" \
  --data-urlencode "kiosk" \
  -o "${RAW_SCREENSHOT}"

"${MAGICK_CMD}" "${RAW_SCREENSHOT}" -trim +repage "${OUTPUT_PATH}"
rm -f "${RAW_SCREENSHOT}"

echo "[*] Dashboard screenshot saved to ${OUTPUT_PATH}"
