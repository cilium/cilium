#!/bin/bash

set -e
set -x

source /opt/cilium/env

envsubst < /opt/cilium/cilium.spec.envsubst > /opt/cilium/cilium.spec
# Remove dash (in case of a version like 1.0.0-rc8)
sed -i -re '/^Version/s/-//g' /opt/cilium/cilium.spec

fedpkg --release f27 local

find /opt/cilium -type f -name 'cilium*.rpm' -exec mv -f "{}" /output/ \;
