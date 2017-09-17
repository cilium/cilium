#!/bin/bash

# Copyright 2014 The Kubernetes Authors.
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

KUBE_ROOT=$(dirname "${BASH_SOURCE}")/..

source "${KUBE_ROOT}/cluster/kube-util.sh"
source "${KUBE_ROOT}/federation/cluster/common.sh"

: "${FEDERATION_HOST_CLUSTER_ZONE?Must set FEDERATION_HOST_CLUSTER_ZONE env var}"

(
    set-federation-zone-vars "${FEDERATION_HOST_CLUSTER_ZONE}"
    # Export FEDERATION_KUBE_CONTEXT to ensure that it is available to
    # ginkgo-e2e.sh and is thus passed on to the federation tests.
    export FEDERATION_KUBE_CONTEXT
    "${KUBE_ROOT}/hack/ginkgo-e2e.sh" $@
)
