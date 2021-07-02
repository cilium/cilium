#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh
source $DIR/../backporting/common.sh

MAJ_REGEX='[0-9]\+\.[0-9]\+'
MIN_REGEX='[0-9]\+\.[0-9]\+\.[0-9]\+'
REGEX_FILTER_DATE='s/^\([-0-9]\+\).*/\1/'
PROJECTS_REGEX='s/.*projects\/\([0-9]\+\).*/\1/'
ACTS_YAML=".github/maintainers-little-helper.yaml"
REMOTE="$(get_remote)"

for release in $(grep "General Announcement" README.rst \
                 | sed 's/.*tree\/\(v'"$MAJ_REGEX"'\).*/\1/'); do
    latest=$(git describe --tags $REMOTE/$release \
             | sed 's/v//' | sed 's/\('"$MIN_REGEX"'\).*/\1/')
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
    new_proj=$(git show $REMOTE/$release:$ACTS_YAML | grep project \
               | sed "$PROJECTS_REGEX")

    echo "Updating $release:"
    echo "  $current on $old_date with project $old_proj to"
    echo "  $latest on $new_date with project $new_proj"
    sed -i 's/\('$release'.*\)'$old_date'/\1'$new_date'/g' README.rst
    sed -i 's/'$current'/'$latest'/g' README.rst
    sed -i 's/\(projects\/\)'$old_proj'/\1'$new_proj'/g' $ACTS_YAML
done

git add README.rst $ACTS_YAML
git commit -s -m "Update stable releases"
