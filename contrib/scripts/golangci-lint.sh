#!/usr/bin/env bash

set -euo pipefail

base_bin="golangci-lint"
custom_dir="tools/golangci-lint-kubeapi"
custom_bin="${custom_dir}/golangci-lint-kubeapi"

# Return golangci-lint's version string. Expected format: v2.6.2 or
# v2.6.2-custom-gcl-<hash>.
get_golangci_version() {
	"$1" version --short 2>/dev/null
}

# Check the version of the custom binary and rebuild if it doesn't match the
# system version.
if [[ -x "${custom_bin}" ]]; then
	base="$(get_golangci_version "${base_bin}")"
	custom="$(get_golangci_version "${custom_bin}")"

	if [[ ! $custom =~ $base ]]; then
		echo "Custom golangci-lint version ${custom} doesn't match system version ${base}, rebuilding..."
		"${base_bin}" custom
	fi
else
	"${base_bin}" custom
fi

echo "golangci-lint run" "$@"
"${base_bin}" run "$@"

echo "golangci-lint-kubeapi run" "$@"
"${custom_bin}" -c "${custom_dir}/golangci-lint-kubeapi.yaml" run ./pkg/k8s/apis/cilium.io/... "$@"
