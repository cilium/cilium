#!/usr/bin/env bash
set -e

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

cd "${dir}"
vagrant provision
make k8s-multi-node-tests
