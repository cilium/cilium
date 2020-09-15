#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

ubuntu_packages=(
  apt-transport-https
  gawk
  ca-certificates
  curl
  gnupg
  grep
  jq
  sed
)

google_packages=(
  google-cloud-sdk
  kubectl
)

export DEBIAN_FRONTEND=noninteractive

apt-get update

ln -fs /usr/share/zoneinfo/UTC /etc/localtime

apt-get install -y --no-install-recommends "${ubuntu_packages[@]}"

echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list
curl --fail --show-error --silent https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -

apt-get update

apt-get install -y --no-install-recommends "${google_packages[@]}"
