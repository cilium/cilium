#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# Copies the Gateway API standard channel CRDs matching the version of
# sigs.k8s.io/gateway-api pinned in go.mod into the operator, where they are
# embedded and optionally installed by the Cilium Operator
# (--gateway-api-install-crds).

set -o errexit
set -o pipefail
set -o nounset

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_ROOT}/../.."
DEST_DIR="${ROOT_DIR}/operator/pkg/gateway-api/crds/standard"

cd "${ROOT_DIR}"

GATEWAY_API_VERSION="$(go list -m -f '{{.Version}}' sigs.k8s.io/gateway-api)"
# The vendor directory doesn't contain the CRD manifests, download the module.
GATEWAY_API_DIR="$(GOFLAGS=-mod=mod go mod download -json "sigs.k8s.io/gateway-api@${GATEWAY_API_VERSION}" | sed -n 's/^\t"Dir": "\(.*\)",$/\1/p')"

if [ -z "${GATEWAY_API_DIR}" ] || [ ! -d "${GATEWAY_API_DIR}/config/crd/standard" ]; then
  echo "Unable to locate Gateway API ${GATEWAY_API_VERSION} CRDs" >&2
  exit 1
fi

find "${DEST_DIR}" -type f -name '*.yaml' -delete

# Only CRDs are copied: the safe-upgrades ValidatingAdmissionPolicy shipped in
# the same directory is left to be installed by users.
for file in "${GATEWAY_API_DIR}"/config/crd/standard/gateway.networking.k8s.io_*.yaml; do
  name="$(basename "${file}")"
  case "${name}" in
    *_vap_*) continue ;;
  esac
  install -m 0644 "${file}" "${DEST_DIR}/${name}"
done
