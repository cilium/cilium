#!/usr/bin/env bash

# Copyright 2019 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# Usage:
#   contrib/go-mod/pin-dependency.sh $MODULE $SHA-OR-TAG
#
# Example:
#   contrib/go-mod/pin-dependency.sh github.com/docker/docker 501cb131a7b7

# Explicitly opt into go modules, even though we're inside a GOPATH directory
export GO111MODULE=on
# Explicitly clear GOFLAGS, since GOFLAGS=-mod=vendor breaks dependency resolution while rebuilding vendor
export GOFLAGS=
# Detect problematic GOPROXY settings that prevent lookup of dependencies

dep="${1:-}"
sha="${2:-}"
if [[ -z "${dep}" || -z "${sha}" ]]; then
  echo "Usage:"
  echo "  contrib/go-mod/pin-dependency.sh \$MODULE \$SHA-OR-TAG"
  echo ""
  echo "Example:"
  echo "  contrib/go-mod/pin-dependency.sh github.com/docker/docker 501cb131a7b7"
  echo ""
  exit 1
fi

KUBE_ROOT="/tmp"

_tmp="${KUBE_ROOT}/_tmp"
cleanup() {
  rm -rf "${_tmp}"
}
trap "cleanup" EXIT SIGINT
cleanup
mkdir -p "${_tmp}"

# Add the require directive
echo "Running: go get ${dep}@${sha}"
go get -d "${dep}@${sha}"

# Find the resolved version
rev=$(go mod edit -json | jq -r ".Require[] | select(.Path == \"${dep}\") | .Version")

# No entry in go.mod, we must be using the natural version indirectly
if [[ -z "${rev}" ]]; then
  # backup the go.mod file, since go list modifies it
  cp go.mod "${_tmp}/go.mod.bak"
  # find the revision
  rev=$(go list -m -json "${dep}" | jq -r .Version)
  # restore the go.mod file
  mv "${_tmp}/go.mod.bak" go.mod
fi

# No entry found
if [[ -z "${rev}" ]]; then
  echo "Could not resolve ${sha}"
  exit 1
fi

echo "Resolved to ${dep}@${rev}"

# Add the replace directive
echo "Running: go mod edit -replace ${dep}=${dep}@${rev}"
go mod edit -replace "${dep}=${dep}@${rev}"

echo ""
echo "Run contrib/go-mod/update-vendor.sh to rebuild the vendor directory"
