#!/bin/bash

set -e

echo "Helm version ${HELM_VERSION}"
export HELM_VERSION="3.1.2"

echo "Installing helm"

if [[ ! $(helm version | grep ${HELM_VERSION}) ]]; then
  retry_function "wget -nv https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz"
  tar xzvf helm-v${HELM_VERSION}-linux-amd64.tar.gz
  mv linux-amd64/helm /usr/local/bin/
fi
helm version
