#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh
source $DIR/../backporting/common.sh

MAJ_REGEX='[0-9]\+\.[0-9]\+'
MIN_REGEX='[0-9]\+\.[0-9]\+\.[0-9]\+'
REGEX_FILTER_DATE='s/^\([-0-9]\+\).*/\1/'
PROJECTS_REGEX='s/.*projects\/\([0-9]\+\).*/\1/'
ACTS_YAML=".github/maintainers-little-helper.yaml"
REMOTE="$(get_remote)"

latest_stable=""
for release in $(grep "Release Notes" README.rst \
                 | sed 's/.*tree\/\(v'"$MAJ_REGEX"'\).*/\1/'); do
    latest=$(git describe --tags $REMOTE/$release \
             | sed 's/v//' | sed 's/\('"$MIN_REGEX"'\).*/\1/')
    if [ -z "$latest_stable" ]; then
        # the first release in the list is the latest stable
        latest_stable=$latest
        echo "v$latest_stable" > stable.txt
        echo '{"results":[{"slug":"v'"$(echo "${latest_stable}" | grep -Eo '[0-9]+\.[0-9]+')"'"}]}' > Documentation/_static/stable-version.json
    fi
    if grep -q -F $latest README.rst; then
        continue
    fi

    current=$(grep -F $release README.rst \
              | sed 's/.*\('"$MIN_REGEX"'\).*/\1/')
    old_date=$(git log -1 -s --format="%cI" $current | sed "$REGEX_FILTER_DATE")
    new_date=$(git log -1 -s --format="%cI" $latest | sed "$REGEX_FILTER_DATE")
    elease=$(echo $release | sed 's/v//')
    old_proj=$(grep -F "$elease" -A 1 $ACTS_YAML | grep projects | sort | uniq \
               | sed "$PROJECTS_REGEX")
    new_proj=$(git show $REMOTE/$release:$ACTS_YAML | grep projects \
               | sed "$PROJECTS_REGEX")

    echo "Updating $release:"
    echo "  $current on $old_date with project $old_proj to"
    echo "  $latest on $new_date with project $new_proj"
    sed -i 's/\('$release'.*\)'$old_date'/\1'$new_date'/g' README.rst
    sed -i 's/v'$current'/v'$latest'/g' README.rst
    sed -i 's/\(projects\/\)'$old_proj'/\1'$new_proj'/g' $ACTS_YAML
done

git add README.rst stable.txt Documentation/_static/stable-version.json $ACTS_YAML
if ! git diff-index --quiet HEAD -- README.rst stable.txt Documentation/_static/stable-version.json $ACTS_YAML; then
    git commit -s -m "Update stable releases"
    echo "README.rst and stable.txt updated, submit the PR now."
else
    echo "No new releases found."
fi
