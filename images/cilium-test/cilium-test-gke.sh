#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

nodes() {
  kubectl get nodes --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}'
}

until [ "$(nodes | wc -l)" -eq  2 ] ; do sleep 5 ; done

index=1
for node in $(nodes) ; do
  kubectl label --overwrite node "${node}" "cilium.io/ci-node=k8s${index}"
  index=$((index+1))
done

kubectl create ns cilium || true

CILIUM_IMAGE="${1}"
CILIUM_OPERATOR_IMAGE="${2}"

export CILIUM_IMAGE CILIUM_OPERATOR_IMAGE

shift 2

CNI_INTEGRATION=gke

K8S_VERSION="$(kubectl version -o json |  jq -r '(.serverVersion.major + "." + (.serverVersion.minor | scan("[0-9]+")))' | sed 's/"//g')"

export CNI_INTEGRATION K8S_VERSION

cd /usr/local/src/cilium/test

cilium-test \
  -test.v \
  -ginkgo.v \
  -ginkgo.noColor \
  -ginkgo.focus="K8s*" \
  -cilium.provision=false \
  -cilium.kubeconfig="${KUBECONFIG}" \
  -cilium.image="${CILIUM_IMAGE}" \
  -cilium.operator-image="${CILIUM_OPERATOR_IMAGE}" \
  -cilium.passCLIEnvironment=true
