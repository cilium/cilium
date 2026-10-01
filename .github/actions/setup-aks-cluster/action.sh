#!/usr/bin/env bash

set -euo pipefail

resource_group="${CLUSTER_NAME}"

read -r -a tag_list <<< "${TAGS}"
read -r -a taint_args <<< "${TAINTS}"

group_args=()
if [[ ${#tag_list[@]} -gt 0 ]]; then
  group_args+=(--tags "${tag_list[@]}")
fi

create_args=()
if [[ -n "${K8S_VERSION}" ]]; then
  create_args+=(--kubernetes-version "${K8S_VERSION}")
fi
if [[ -n "${OS_SKU}" ]]; then
  create_args+=(--os-sku "${OS_SKU}")
fi

# Create group
az group create \
  --name "${resource_group}" \
  --location "${LOCATION}" \
  "${group_args[@]}"

# Create AKS cluster. The PodCIDRs must match the ranges managed by the
# CNI so the control plane can route traffic to pods.
az aks create \
  --resource-group "${resource_group}" \
  --name "${CLUSTER_NAME}" \
  --location "${LOCATION}" \
  "${create_args[@]}" \
  --network-plugin none \
  --node-count "$(( NODE_COUNT + 2 ))" \
  --ip-families ipv4,ipv6 \
  --pod-cidrs "${POD_CIDRS}" \
  "${taint_args[@]}" \
  --generate-ssh-keys \
  --api-server-authorized-ip-ranges "${AUTHORIZED_IP_RANGES}"
