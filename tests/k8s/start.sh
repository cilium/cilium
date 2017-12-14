#!/usr/bin/env bash
set -e

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

cd "${dir}"
VAGRANT_DEFAULT_PROVIDER=virtualbox vagrant provision
make k8s-multi-node-tests
