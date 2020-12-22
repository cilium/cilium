#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

HELM_VERSION=3.3.4

TARGETPLATFORM="${1}"

target="$(echo "${TARGETPLATFORM}" | tr / -)"

curl --fail --show-error --silent --location \
     "https://get.helm.sh/helm-v${HELM_VERSION}-${target}.tar.gz" \
   --output /tmp/helm.tgz

tar -xf /tmp/helm.tgz -C /tmp

ls -laR /tmp

mv "/tmp/${target}/helm" /usr/local/bin

rm -rf /tmp/helm.tgz "/tmp/${target}"
