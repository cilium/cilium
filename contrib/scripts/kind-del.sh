#!/usr/bin/env bash
#
# Tear down the kind cluster and docker network created by
# contrib/scripts/kind-dsr.sh so it can be re-run from scratch.

set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-kind}"
NETWORK_NAME="${KIND_EXPERIMENTAL_DOCKER_NETWORK:-kind-cilium}"

if command -v kind >/dev/null 2>&1; then
  if kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
    kind delete cluster --name "${CLUSTER_NAME}"
  fi
fi

if docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1; then
  docker network rm "${NETWORK_NAME}" >/dev/null
fi
