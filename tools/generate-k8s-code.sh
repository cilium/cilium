#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
export GO111MODULE=auto

file_permissions=$(stat -c%a "${dir}/../vendor/k8s.io/code-generator/generate-groups.sh")
cleanup() {
  chmod ${file_permissions} "${dir}/../vendor/k8s.io/code-generator/generate-groups.sh"
}
trap "cleanup" EXIT SIGINT
cd "${dir}/../vendor/k8s.io/code-generator"
chmod +x ./generate-groups.sh
./generate-groups.sh "$@"

