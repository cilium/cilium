#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
redirect_txt="${script_dir}/redirects.txt"

if ! git diff --quiet -- "${redirect_txt}" ; then
    git --no-pager diff "${redirect_txt}"
    echo "HINT: to fix this, run 'make -C Documentation update-redirects'"
    exit 1
fi
