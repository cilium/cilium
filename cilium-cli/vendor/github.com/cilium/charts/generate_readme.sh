#!/bin/bash

set -e

cat << EOF
This repository holds helm templates for the following Cilium releases:

EOF

for version in \
    $(find -- * -name 'cilium-*.tgz' ! -name "*dev*" \
    | cut -d - -f 2- \
    | xargs basename -s .tgz \
    | sed '/-/!{s/$/_/;}' \
    | sort -Vr \
    | sed 's/_$//'); do
  echo "* [v$version](https://github.com/cilium/cilium/releases/tag/v$version) (_[source](https://github.com/cilium/cilium/tree/v$version/install/kubernetes/cilium)_)"
done

cat << EOF

This repository holds helm templates for the following Tetragon releases:

EOF

for version in \
    $(find -- * -name 'tetragon-*.tgz' ! -name "*dev*" \
    | cut -d - -f 2- \
    | xargs basename -s .tgz \
    | sed '/-/!{s/$/_/;}' \
    | sort -Vr \
    | sed 's/_$//'); do
  # Tetragon chart was moved in 1.1 release
  TETRAGON_CHART_DIR="install/kubernetes/tetragon"
  MAJOR=$(echo "$version" | cut -d. -f1)
  MINOR=$(echo "$version" | cut -d. -f2)
  if [ "$MAJOR" -lt 1 ] || ([ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 1 ]); then
    TETRAGON_CHART_DIR="install/kubernetes"
  fi
  echo "* [v$version](https://github.com/cilium/tetragon/releases/tag/v$version) (_[source](https://github.com/cilium/tetragon/tree/v$version/$TETRAGON_CHART_DIR)_)"
done

cat << EOF
