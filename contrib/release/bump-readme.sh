#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source "$DIR/../backporting/common.sh"

BUMP_README="${DIR}/../../tools/bump-readme"
MAJ_REGEX='[0-9]\+\.[0-9]\+'
VER_REGEX='[0-9]\+\.[0-9]\+\.[0-9]\+\(-\(pre\|rc\)\.[0-9]\+\)\?'
REMOTE="$(get_remote)"

set -e
set -u
set -o pipefail

pull_versions() {
    gh api \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        /repos/cilium/cilium/releases \
    | jq '.[] | {"version": .tag_name, "date": .created_at}' \
    | jq -s
}

# $1 - git tree path to commit object, eg tree/ or commits/
check_table() {
    obj_regex="$1"

    readarray -t table < <(grep -C 1 "$obj_regex" README.rst)

    len=""
    for line in "${table[@]}"; do
        if [ -z $len ]; then
            len="$(echo $line | wc -c)"
            continue
        fi
        if [ "$(echo "$line" | wc -c)" != "$len" ]; then
            >&2 echo "The following table is malformed, please fix it:"
            for l in "${table[@]}"; do
                >&2 echo "$l"
            done
            exit 1
        fi
    done
}

update_stable_versions() {
    local release

    release=$(grep "Release Notes" README.rst \
              | sed 's/.*tree\/\(v'"$MAJ_REGEX"'\).*/\1/' \
              | head -n 1)

    # the first release in the list is the latest stable
    latest=$(git describe --tags "$REMOTE/$release" \
             | sed 's/v//' | sed 's/\('"$VER_REGEX"'\).*/\1/')

    echo "v$latest" > stable.txt
    echo '{"results":[{"slug":"v'"$(echo "${latest}" \
    | grep -Eo '[0-9]+\.[0-9]+')"'"}]}' \
    > Documentation/_static/stable-version.json
}

main() {
    versions="$(mktemp)"
    trap 'rm $versions' EXIT

    pull_versions > "$versions"

    go run "$BUMP_README" --versions "$versions" < README.rst > README.rst.new
    mv README.rst{.new,}

    update_stable_versions
    check_table "releases/tag/v"

    git add README.rst stable.txt Documentation/_static/stable-version.json
    if ! git diff-index --quiet HEAD -- README.rst stable.txt Documentation/_static/stable-version.json; then
        git commit -s -m "README: Update releases"
        echo "README.rst and stable.txt updated, submit the PR now."
    else
        echo "No new releases found."
    fi
}

main "@"
