#!/usr/bin/env bash
set -exv

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

cd "${dir}"
# Clean up VMs that were already running in case something went wrong in a prior build.
vagrant destroy -f
VAGRANT_DEFAULT_PROVIDER=virtualbox vagrant up --provider=virtualbox
make k8s-multi-node-tests
