#!/usr/bin/env bash

set -euo pipefail

GOLANGCI_LINT_BIN="${GOLANGCI_LINT_BIN:-golangci-lint}"
GOLANGCI_LINT_ARGS="${GOLANGCI_LINT_ARGS:-}"
GOLANGCI_LINT_MODULE="${GOLANGCI_LINT_MODULE:-golangci-lint-cilium}"
GOLANGCI_LINT_DIR="${GOLANGCI_LINT_DIR:-tools/golangci-lint}"

# If the golangci-lint custom module binary does NOT exist,
# build the custom golangci-lint module using `golangci-lint custom`.
if  [ ! -x "${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" ]; then
	"${GOLANGCI_LINT_BIN}" custom
fi

# Execute lint with custom binary
"${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" run ${GOLANGCI_LINT_ARGS} --disable=kubeapilinter
"${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" run ${GOLANGCI_LINT_ARGS} --enable-only=kubeapilinter ./pkg/k8s/apis/cilium.io/...