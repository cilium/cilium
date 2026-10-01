#!/usr/bin/env bash

set -euo pipefail

resource_group="${CLUSTER_NAME}"
interval=30

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

# Both attempts, the teardown between them and the node waits in the
# steps below all share this step's timeout-minutes.
budget=$(( TIMEOUT_MINUTES * 60 ))
required=$(( ATTEMPT_DEADLINE + RETRY_DEADLINE + 820 ))
if [ "${budget}" -lt "${required}" ]; then
  echo "::error::timeout_minutes gives ${budget}s and the create needs ${required}s"
  exit 1
fi

# Submit one create and poll it. 0 provisioned, 1 hit the deadline,
# 2 ended somewhere a retry cannot clear.
create_and_wait() {
  cluster="$1"
  deadline="$2"
  started="${SECONDS}"
  state=unknown

  # The PodCIDRs must match the ranges managed by the CNI so the
  # control plane can route traffic to pods.
  timeout 300 az aks create \
    --resource-group "${resource_group}" \
    --name "${cluster}" \
    --location "${LOCATION}" \
    "${create_args[@]}" \
    --network-plugin none \
    --node-count "$(( NODE_COUNT + 2 ))" \
    --ip-families ipv4,ipv6 \
    --pod-cidrs "${POD_CIDRS}" \
    "${taint_args[@]}" \
    --generate-ssh-keys \
    --api-server-authorized-ip-ranges "${AUTHORIZED_IP_RANGES}" \
    --no-wait || return 2

  echo "waiting up to ${deadline}s for ${cluster} to provision"
  while true; do
    elapsed=$(( SECONDS - started ))

    # Checked before the query below, so a slow az cannot overshoot it.
    if [ "${elapsed}" -ge "${deadline}" ]; then
      echo "::error::cluster ${cluster} still ${state} after ${elapsed}s, abandoning"
      # --no-wait, because cancelling an AKS create starts another long
      # running operation.
      timeout 60 az aks operation-abort \
        --resource-group "${resource_group}" \
        --name "${cluster}" --no-wait || true
      return 1
    fi

    # Bounded, so a hung az still lets the deadline check above run.
    state="$(timeout 60 az aks show \
      --resource-group "${resource_group}" \
      --name "${cluster}" \
      --query provisioningState -o tsv 2>/dev/null || true)"
    [ -n "${state}" ] || state=ShowFailed
    echo "${cluster} provisioningState=${state} (${elapsed}s)"

    case "${state}" in
      Succeeded)
        return 0
        ;;
      Failed|Canceled)
        echo "::error::cluster ${cluster} ended in ${state} after ${elapsed}s"
        return 2
        ;;
    esac

    sleep "${interval}"
  done
}

# az aks create refuses a name that already exists, so each attempt
# takes a fresh cluster inside the one resource group.
attempt=0
winner=""
for deadline in "${ATTEMPT_DEADLINE}" "${RETRY_DEADLINE}"; do
  attempt=$(( attempt + 1 ))
  candidate="${resource_group}-a${attempt}"
  rc=0
  create_and_wait "${candidate}" "${deadline}" || rc=$?
  if [ "${rc}" -eq 0 ]; then
    winner="${candidate}"
    break
  fi
  if [ "${rc}" -eq 2 ]; then
    break
  fi
  echo "attempt ${attempt} never left Creating, trying a fresh cluster"
done

if [ -z "${winner}" ]; then
  echo "::error::no cluster provisioned after ${attempt} attempts"
  exit 1
fi
echo "provisioned ${winner} after ${attempt} attempt(s)"
echo "cluster_name=${winner}" >> "${GITHUB_OUTPUT}"
