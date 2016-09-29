#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../../examples/kubernetes/env-kube.sh"

K8S_PATH="/home/vagrant/kubernetes"

desc "Run kubernetes and wait until it's ready"
run "cd ${K8S_PATH} && ./hack/local-up-cluster.sh"
