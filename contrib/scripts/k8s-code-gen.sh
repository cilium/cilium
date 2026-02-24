#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/../.."
CODEGEN_PKG=${CODEGEN_PKG:-$(cd "${SCRIPT_ROOT}"; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../code-generator)}

echo SCRIPT_ROOT=${SCRIPT_ROOT}

source "${CODEGEN_PKG}/kube_codegen.sh"

TMPDIR=${1}
PLURAL_EXCEPTIONS="Endpoints:Endpoints,ResourceClaimParameters:ResourceClaimParameters,ResourceClassParameters:ResourceClassParameters"

# This is adapted from the kube::codegen::gen_helper function in kube_codegen.sh
# The main reason is to accommodate custom deepequal-gen generator
# from https://github.com/cilium/deepequal-gen
function kube::codegen::deepequal_helpers() {
    local in_dir=""
    local boilerplate="${KUBE_CODEGEN_ROOT}/hack/boilerplate.go.txt"
    local v="${KUBE_VERBOSE:-0}"
    local output_base=""

    while [ "$#" -gt 0 ]; do
        case "$1" in
            "--boilerplate")
                boilerplate="$2"
                shift 2
                ;;
            "--output-base")
                output_base="$2"
                shift 2
                ;;
            *)
                if [[ "$1" =~ ^-- ]]; then
                    echo "unknown argument: $1" >&2
                    return 1
                fi
                if [ -n "$in_dir" ]; then
                    echo "too many arguments: $1 (already have $in_dir)" >&2
                    return 1
                fi
                in_dir="$1"
                shift
                ;;
        esac
    done

    if [ -z "${in_dir}" ]; then
        echo "input-dir argument is required" >&2
        return 1
    fi

    local input_pkgs=()
    while read -r dir; do
        pkg="$(cd "${dir}" && GO111MODULE=on go list -find .)"
        input_pkgs+=("${pkg}")
    done < <(
        ( kube::codegen::internal::grep -l --null \
            -e '^\s*//\s*+deepequal-gen=' \
            -r "${in_dir}" \
            --include '*.go' \
            || true \
        ) | while read -r -d $'\0' F; do dirname "${F}"; done \
          | LC_ALL=C sort -u
    )

    if [ "${#input_pkgs[@]}" != 0 ]; then
        echo "Generating deepequal code for ${#input_pkgs[@]} targets"

        kube::codegen::internal::findz \
            "${in_dir}" \
            -path ./vendor -prune \
            -type f \
            -name zz_generated.deepequal.go \
            | xargs -0 rm -f

        go run github.com/cilium/deepequal-gen \
            -v "${v}" \
            --output-file zz_generated.deepequal.go \
            --go-header-file "${boilerplate}" \
            --output-base "${output_base}" \
            "${input_pkgs[@]}"
    fi
}

kube::codegen::gen_client \
    "./pkg/k8s/slim/k8s/api" \
    --with-watch \
    --output-dir "${TMPDIR}/github.com/cilium/cilium/pkg/k8s/slim/k8s/client" \
    --output-pkg "github.com/cilium/cilium/pkg/k8s/slim/k8s/client" \
    --plural-exceptions ${PLURAL_EXCEPTIONS} \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt"

kube::codegen::gen_client \
    "./pkg/k8s/slim/k8s/apis" \
    --with-watch \
    --output-dir "${TMPDIR}/github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client" \
    --output-pkg "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client" \
    --plural-exceptions ${PLURAL_EXCEPTIONS} \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt"

kube::codegen::gen_client \
    "./pkg/k8s/apis" \
    --with-watch \
    --output-dir "${TMPDIR}/github.com/cilium/cilium/pkg/k8s/client" \
    --output-pkg "github.com/cilium/cilium/pkg/k8s/client" \
    --plural-exceptions ${PLURAL_EXCEPTIONS} \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt"

cp -r "${TMPDIR}/github.com/cilium/cilium/." ./

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt" \
    "$PWD/api"

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt" \
    "$PWD/pkg"

kube::codegen::deepequal_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt" \
    --output-base "${TMPDIR}" \
    "$PWD"

cp -r "${TMPDIR}/github.com/cilium/cilium/." ./
