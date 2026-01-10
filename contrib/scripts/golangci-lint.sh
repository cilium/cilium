#!/usr/bin/env bash

set -euo pipefail

GOLANGCI_LINT_BIN="${GOLANGCI_LINT_BIN:-golangci-lint}"
GOLANGCI_LINT_ARGS="${GOLANGCI_LINT_ARGS:-}"
GOLANGCI_LINT_MODULE="${GOLANGCI_LINT_MODULE:-golangci-lint-cilium}"
GOLANGCI_LINT_DIR="${GOLANGCI_LINT_DIR:-tools/golangci-lint}"

# Extract the version string from "golangci-lint --version" output.
# Expected format:
#   golangci-lint has version <version> built with ...
# Returns only the <version> part (e.g., v2.6.2 or v2.6.2-custom-gcl-<hash>)
get_golangci_version() {
	"$1" --version 2>/dev/null | sed -n 's/^golangci-lint has version \([^ ]*\).*/\1/p'
}

# If the custom binary already exists:
# - Parse the base version of the system-installed golangci-lint
# - Parse the base version of the custom-built golangci-lint
# - If they differ, remove the old custom binary to trigger a rebuild
if [[ -x "${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" ]]; then
	BASE_VERSION="$(get_golangci_version "${GOLANGCI_LINT_BIN}" || true)"
	CUSTOM_VERSION_RAW="$(get_golangci_version "${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" || true)"

	# Custom version looks like:
	#   vX.Y.Z-custom-gcl-<hash>
	# Strip the "-custom-gcl-..." suffix to get the base version.
	CUSTOM_BASE_VERSION="${CUSTOM_VERSION_RAW%%-custom-gcl-*}"

	# Rebuild the custom binary if:
	# - version extraction failed, or
	# - base versions do not match
	if [[ -z "${BASE_VERSION}" || -z "${CUSTOM_BASE_VERSION}" || "${BASE_VERSION}" != "${CUSTOM_BASE_VERSION}" ]]; then
		rm -f "${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}"
	fi
fi

# If the golangci-lint custom module binary does NOT exist,
# build the custom golangci-lint module using `golangci-lint custom`.
if  [ ! -x "${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" ]; then
	"${GOLANGCI_LINT_BIN}" custom
fi

# Execute lint with custom binary
"${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" run ${GOLANGCI_LINT_ARGS} --disable=kubeapilinter
"${GOLANGCI_LINT_DIR}/${GOLANGCI_LINT_MODULE}" run ${GOLANGCI_LINT_ARGS} --enable-only=kubeapilinter ./pkg/k8s/apis/cilium.io/...