#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd "${script_dir}/.." && pwd)"
target_file="${source_dir}/Documentation/Makefile"

make -C "${script_dir}" update-docs-builder-image

git add --intent-to-add -- "$target_file"
if ! git diff --quiet -- "$target_file"; then
    git --no-pager diff "$target_file"
    echo "HINT: to fix this, run 'make -C Documentation builder-image'"
    exit 1
fi
