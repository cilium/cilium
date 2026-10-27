#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -o errexit
set -o pipefail
set -o nounset

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/scripts/run-gh-ginkgo-workflow.sh
source "${script_dir}/run-gh-ginkgo-workflow.sh"

test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT

write_helm() {
    local destination="$1" version="$2"
    printf '#!/bin/bash\nprintf "%%s\\n" "v%s+fixture"\n' "${version}" > "${destination}"
    chmod +x "${destination}"
}

run_case() (
    local name="$1" installed_version="$2" location="$3" expect_download="$4"
    local case_dir="${test_root}/${name}"
    mkdir -p "${case_dir}/bin" "${case_dir}/work" "${case_dir}/download"
    for tool in cp cut; do
        ln -s "$(command -v "${tool}")" "${case_dir}/bin/${tool}"
    done
    write_helm "${case_dir}/downloaded-helm" "${helm_version}"
    if [[ "${installed_version}" != missing ]]; then
        if [[ "${location}" == staged || "${location}" == relative ]]; then
            write_helm "${case_dir}/work/helm" "${installed_version}"
        else
            write_helm "${case_dir}/bin/helm" "${installed_version}"
        fi
    fi
    cd "${case_dir}/work"
    tmpdir="${case_dir}/download"
    install_helm() {
        printf 'downloaded\n' > "${case_dir}/download-called"
        cp "${case_dir}/downloaded-helm" "${tmpdir}/helm"
    }
    case "${location}" in
        staged) PATH="${PWD}:${case_dir}/bin" ;;
        relative) PATH="../work:${case_dir}/bin" ;;
        *) PATH="${case_dir}/bin" ;;
    esac
    export PATH
    stage_helm
    [[ -x ./helm ]]
    [[ "$(./helm version --short)" == "v${helm_version}+fixture" ]]
    if [[ "${expect_download}" == yes ]]; then
        [[ -f "${case_dir}/download-called" ]]
    else
        [[ ! -f "${case_dir}/download-called" ]]
    fi
    printf 'ok - %s\n' "${name}"
)

run_case missing-helm missing external yes
run_case helm3-replaced 3.21.3 external yes
run_case different-helm4-replaced 4.2.3 external yes
run_case matching-helm-reused "${helm_version}" external no
run_case staged-helm-reused "${helm_version}" staged no
run_case relative-staged-helm-reused "${helm_version}" relative no
