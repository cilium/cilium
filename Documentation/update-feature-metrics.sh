#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd "${script_dir}/.." && pwd)"
tmp_dir="$(mktemp -d)"
observability_dir="${script_dir}/observability"
helm_generator="${source_dir}/tools/feature-helm-generator/feature-helm-generator"

# cilium-agent
${source_dir}/daemon/cilium-agent metrics dump features "${tmp_dir}"
${helm_generator} --prom-file "${tmp_dir}/cilium-agent.feature-metrics.prom" \
    --metrics-prefix cilium_feature \
    --metrics-separators adv_connect_and_lb,controlplane,datapath,network_policies \
    > "${observability_dir}/feature-metrics-agent.txt"

# cilium-operator
${source_dir}/operator/cilium-operator metrics dump features "${tmp_dir}"
${helm_generator} --prom-file "${tmp_dir}/cilium-operator.feature-metrics.prom" \
    --metrics-prefix cilium_operator_feature \
    --metrics-separators adv_connect_and_lb \
    > "${observability_dir}/feature-metrics-operator.txt"
