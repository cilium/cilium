#!/bin/bash

set -e
set -x

source /opt/cilium/env

envsubst < /opt/cilium/cilium.spec.envsubst > /opt/cilium/cilium.spec
fedpkg --release f26 local
set +x

find /opt/cilium -type f -name 'cilium*.rpm' -exec mv -f "{}" /output/ \;

echo
echo "Cilium version ${VERSION} packages can be found in output/ directory"
echo
