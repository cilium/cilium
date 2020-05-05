#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd "${script_dir}/.." && pwd)"
examples_dir="${source_dir}/examples"
cilium="${source_dir}/cilium/cilium"

JSON_FILES=$(find ${examples_dir} \
             -wholename "*/policies/*.json" \
             -o -wholename "*/demo/*.json")
YAML_FILES=$(find ${examples_dir}/policies -name "*.yaml")

for f in $JSON_FILES; do
    ${cilium} policy validate --verbose=false "$f"
done

for f in $YAML_FILES; do
    yamllint -c "$script_dir/yaml.config" "$f"
done
