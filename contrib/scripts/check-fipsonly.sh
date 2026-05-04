#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eu

EXCLUDED_DIRS=(
    "cilium-health/responder"
    "contrib/examples/statedb"
    "contrib/examples/statedb_k8s"
    "images/builder"
    "pkg/datapath/loader/tools"
    "pkg/k8s/resource/example"
    "pkg/loadbalancer/benchmark/cmd"
    "pkg/loadbalancer/repl"
    "tools/alignchecker"
    "tools/api-flaggen"
    "tools/complexity-diff"
    "tools/crdcheck"
    "tools/crdlistgen"
    "tools/dev-doctor"
    "tools/dpgen"
    "tools/feature-helm-generator"
    "tools/legacyhguardcheck"
    "tools/licensecheck"
    "tools/licensegen"
    "tools/mount"
    "tools/slogloggercheck"
    "tools/spdxconv"
    "tools/sysctlfix"
    "tools/testowners"
)

FIPSONLY_EXAMPLE=$(
    cat <<EOT
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build boringcrypto

package main

// Package fipsonly restricts all TLS configuration to FIPS-approved settings.
// See https://github.com/golang/go/blob/master/src/crypto/tls/fipsonly/fipsonly.go
import _ "crypto/tls/fipsonly"
EOT
)

REQUIRED_LINES=(
    "//go:build boringcrypto"
    "import _ \"crypto/tls/fipsonly\""
)

main_packages() {
    grep -lr --include="*.go" --exclude-dir="vendor" "package main" |
        xargs dirname |
        sort -u
}

has_error=0

for package in $(main_packages); do
    # Skip excluded directories
    for excluded in "${EXCLUDED_DIRS[@]}"; do
        if [[ "${package}" == "${excluded}" ]]; then
            echo "Skipping excluded package ${package}"
            continue 2
        fi
    done

    echo "Inspecting package ${package}"
    if [[ -f "${package}/fipsonly.go" ]]; then
        # check if the file contains the required lines
        for line in "${REQUIRED_LINES[@]}"; do
            if ! grep -q "${line}" "${package}/fipsonly.go"; then
                echo >&2 "::error file=${package}/fipsonly.go,line=1,col=1::File ${package}/fipsonly.go is missing required line: '${line}'"
                has_error=1
                continue 2
            fi
        done
        echo "File ${package}/fipsonly.go is valid"
    else
        echo >&2 "::error::File ${package}/fipsonly.go is missing"
        has_error=1
        continue 2
    fi
done

if [ $has_error -eq 1 ]; then
    echo >&2 "::error::FIPSONLY check failed. Please ensure that all main packages either have a 'fipsonly.go' file or are added to the exclusion list in ./contrib/scripts/check-fipsonly.sh"
    echo >&2 "Example fipsonly.go file content:"
    echo >&2 "$FIPSONLY_EXAMPLE"
    exit 1
else
    echo "FIPSONLY check passed"
fi
