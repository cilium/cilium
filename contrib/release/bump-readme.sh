#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh
source $DIR/../backporting/common.sh

set -e
set -o pipefail

MAJ_REGEX='[0-9]\+\.[0-9]\+'
VER_REGEX='[0-9]\+\.[0-9]\+\.[0-9]\+\(-\(pre\|rc\)\.[0-9]\+\)\?'
PRE_REGEX='[0-9]\+\.[0-9]\+\.[0-9]\+-\(pre\|rc\)\.[0-9]\+'
REGEX_FILTER_DATE='s/^\([-0-9]\+\).*/\1/'
PROJECTS_REGEX='s/.*projects\/\([0-9]\+\).*/\1/'
ACTS_YAML=".github/maintainers-little-helper.yaml"
REMOTE="$(get_remote)"

latest_stable=""

# $1 - release branch
# $2 - latest release for the target branch (maybe vX.Y+1* for prerelease)
# #3 - git tree path to commit object, eg tree/ or commits/
# $4 - regex to strip out constant release info from a release line
update_release() {
    old_branch="$1"
    latest="$2"
    obj_regex="$3"
    rem_branch_regex="$4"

    new_branch=$(echo $latest | sed 's/\('$MAJ_REGEX'\).*/v\1/')
    current=$(grep "$obj_regex$old_branch" README.rst \
              | sed 's/^.*'"$obj_regex"'.*tag\/v\('"$rem_branch_regex"'\).*$/\1/')
    old_date=$(git log -1 -s --format="%cI" v$current | sed "$REGEX_FILTER_DATE")
    new_date=$(git log -1 -s --format="%cI" $latest | sed "$REGEX_FILTER_DATE")
    elease=$(echo $old_branch | sed 's/v//')

    old_proj=""
    new_proj=""
    if grep -qF "$elease" $ACTS_YAML; then
        old_proj=$(grep -F "$elease" -A 1 $ACTS_YAML | grep projects | sort | uniq \
                   | sed "$PROJECTS_REGEX")
        new_proj=$(git show $REMOTE/$old_branch:$ACTS_YAML | grep projects \
                   | sed "$PROJECTS_REGEX")
    fi

    printf "%10s %10s %10s %10s\n" "current" "old_date" "new_date" "elease"
    printf "%10s %10s %10s %10s\n" $current  $old_date  $new_date  $elease

    echo "Updating $old_branch:"
    echo "  $current on $old_date with project $old_proj to"
    echo "  $latest on $new_date with project $new_proj"
    sed -i '/'$obj_regex'/s/'$old_branch'\(.*\)'$old_date'/'$new_branch'\1'$new_date'/g' README.rst
    sed -i '/'$obj_regex'/s/v'$current'/v'$latest'/g' README.rst
    if [ -n $old_proj ]; then
        sed -i 's/\(projects\/\)'$old_proj'/\1'$new_proj'/g' $ACTS_YAML
    fi
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

for release in $(grep "Release Notes" README.rst \
                 | sed 's/.*tree\/\(v'"$MAJ_REGEX"'\).*/\1/'); do
    latest=$(git describe --tags $REMOTE/$release \
             | sed 's/v//' | sed 's/\('"$VER_REGEX"'\).*/\1/')
    if [ -z "$latest_stable" ]; then
        # the first release in the list is the latest stable
        latest_stable=$latest
        echo "v$latest_stable" > stable.txt
        echo '{"results":[{"slug":"v'"$(echo "${latest_stable}" | grep -Eo '[0-9]+\.[0-9]+')"'"}]}' > Documentation/_static/stable-version.json
    fi
    if grep -q -F $latest README.rst; then
        continue
    fi

    update_release $release $latest "tree\/" "$VER_REGEX"
done
check_table "tree/v1"

for release in $(grep "$PRE_REGEX" README.rst \
                 | sed 's/.*commits\/\(v'"$MAJ_REGEX"'\).*/\1/'); do
    latest=$(git describe --tags $REMOTE/main \
             | sed 's/v//' | sed 's/\('"$PRE_REGEX"'\).*/\1/')
    if grep -q -F $latest README.rst; then
        continue
    fi

    update_release $release $latest "commits\/" "$PRE_REGEX"
done
check_table "commits/v1"

git add README.rst stable.txt Documentation/_static/stable-version.json $ACTS_YAML
if ! git diff-index --quiet HEAD -- README.rst stable.txt Documentation/_static/stable-version.json $ACTS_YAML; then
    git commit -s -m "README: Update releases"
    echo "README.rst and stable.txt updated, submit the PR now."
else
    echo "No new releases found."
fi
