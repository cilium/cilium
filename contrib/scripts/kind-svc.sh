#!/usr/bin/env bash
#
# Deploy an nginx LoadBalancer service on top of the kind cluster created
# by kind-dsr.sh.
#
# Layout:
#   * 3 of the 4 kind nodes are labelled "service.cilium.io/node=beefy".
#     The 4th node (kind-worker3) is left unlabelled and acts as the
#     "external client" entry point for the north/south path.
#   * 2 nginx backends are scheduled on the beefy nodes (anti-affinity).
#   * The Service is annotated:
#       service.cilium.io/type            = LoadBalancer
#       service.cilium.io/forwarding-mode = dsr
#       service.cilium.io/node            = beefy
#   * The LoadBalancer IP is L2-announced from the beefy nodes only and
#     allocated from a /28 carved out of the kind-cilium docker network.

set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-kind}"
NETWORK_NAME="${KIND_EXPERIMENTAL_DOCKER_NETWORK:-kind-cilium}"
NS="${NS:-default}"
EXTERNAL_NODE="${EXTERNAL_NODE:-${CLUSTER_NAME}-worker3}"

# Compute the LB pool CIDR from the kind-cilium docker network (e.g.
# 172.18.0.0/16 -> 172.18.255.200/28). Same trick as Makefile.kind.
KIND_NET_CIDR="$(docker network inspect "${NETWORK_NAME}" \
  -f '{{json .IPAM.Config}}' \
  | jq -r '.[] | select(.Subnet | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")) | .Subnet')"
if [[ -z "${KIND_NET_CIDR}" ]]; then
  echo "Could not find an IPv4 subnet on docker network ${NETWORK_NAME}" >&2
  exit 1
fi
LB_CIDR="$(echo "${KIND_NET_CIDR}" | sed 's@0.0/16@255.200/28@')"
echo "kind-cilium subnet: ${KIND_NET_CIDR}"
echo "LB pool CIDR:       ${LB_CIDR}"

# Label 3 of the 4 nodes as beefy. The 4th (EXTERNAL_NODE) stays unlabelled
# so the service is NOT installed in its datapath -- this is our external
# client entry point.
mapfile -t NODES < <(kind get nodes --name "${CLUSTER_NAME}")
for n in "${NODES[@]}"; do
  if [[ "${n}" == "${EXTERNAL_NODE}" ]]; then
    kubectl label node "${n}" service.cilium.io/node- >/dev/null 2>&1 || true
    echo "node ${n}: external client (no beefy label)"
  else
    kubectl label node "${n}" service.cilium.io/node=beefy --overwrite >/dev/null
    echo "node ${n}: beefy"
  fi
done

kubectl apply -f - <<EOF
---
apiVersion: cilium.io/v2
kind: CiliumLoadBalancerIPPool
metadata:
  name: nginx-pool
spec:
  blocks:
  - cidr: "${LB_CIDR}"
---
apiVersion: cilium.io/v2alpha1
kind: CiliumL2AnnouncementPolicy
metadata:
  name: nginx-l2
spec:
  serviceSelector:
    matchLabels:
      app: nginx
  nodeSelector:
    matchLabels:
      service.cilium.io/node: beefy
  loadBalancerIPs: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: ${NS}
  labels:
    app: nginx
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      nodeSelector:
        service.cilium.io/node: beefy
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchLabels:
                app: nginx
            topologyKey: kubernetes.io/hostname
      containers:
      - name: nginx
        image: nginx:1.27
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx
  namespace: ${NS}
  labels:
    app: nginx
  annotations:
    service.cilium.io/type: LoadBalancer
    service.cilium.io/forwarding-mode: dsr
    service.cilium.io/node: beefy
spec:
  type: LoadBalancer
  selector:
    app: nginx
  ports:
  - name: http
    port: 80
    targetPort: 80
EOF

echo
echo "Waiting for nginx backends to become ready..."
kubectl -n "${NS}" rollout status deployment/nginx --timeout=120s

echo
echo "Waiting for LoadBalancer IP to be assigned..."
for _ in $(seq 1 30); do
  LB_IP="$(kubectl -n "${NS}" get svc nginx \
    -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
  [[ -n "${LB_IP}" ]] && break
  sleep 2
done

echo
kubectl -n "${NS}" get svc nginx -o wide
echo
kubectl -n "${NS}" get pods -l app=nginx -o wide
echo
if [[ -n "${LB_IP:-}" ]]; then
  echo "LoadBalancer IP: ${LB_IP}"
  echo "Test from the external-client node (no service in its datapath):"
  echo "  docker exec ${EXTERNAL_NODE} curl -sS http://${LB_IP}"
else
  echo "WARNING: no LoadBalancer IP was assigned yet."
fi
