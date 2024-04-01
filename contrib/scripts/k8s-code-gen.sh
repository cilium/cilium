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
