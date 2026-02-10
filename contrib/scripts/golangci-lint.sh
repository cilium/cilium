#!/usr/bin/env bash

set -euo pipefail

GOLANGCI_LINT_BIN="${GOLANGCI_LINT_BIN:-golangci-lint}"
GOLANGCI_LINT_ARGS="${GOLANGCI_LINT_ARGS:-}"
GOLANGCI_LINT_MODULE="${GOLANGCI_LINT_MODULE:-golangci-lint-kubeapi}"
GOLANGCI_LINT_DIR="${GOLANGCI_LINT_DIR:-tools/golangci-lint-kubeapi}"

# Return golangci-lint's version string. Expected format: v2.6.2 or
# v2.6.2-custom-gcl-<hash>.
get_golangci_version() {
	"$1" version --short 2>/dev/null
}

# Check the version of the custom binary and rebuild if it doesn't match the
# system version.
if [[ -x "${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" ]]; then
	base="$(get_golangci_version "${GOLANGCI_LINT_BIN}")"
	custom="$(get_golangci_version "${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}")"

	if [[ $custom =~ $base ]]; then
		echo "Custom golangci-lint ${custom} matches system version ${base}"
	else
		echo "Custom golangci-lint version ${custom} doesn't match system version ${base}, rebuilding..."
		"${GOLANGCI_LINT_BIN}" custom
	fi
else
	"${GOLANGCI_LINT_BIN}" custom
fi

# Execute lint with custom binary
"${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" run ${GOLANGCI_LINT_ARGS} --disable=kubeapilinter
"${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" run ${GOLANGCI_LINT_ARGS} --enable-only=kubeapilinter ./pkg/k8s/apis/cilium.io/...
