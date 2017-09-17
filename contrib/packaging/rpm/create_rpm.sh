#!/bin/bash

set -e
set -x

source /opt/cilium/env

envsubst < /opt/cilium/cilium.spec.envsubst > /opt/cilium/cilium.spec
fedpkg --release f26 local

find /opt/cilium -type f -name 'cilium*.rpm' -exec mv -f "{}" /output/ \;
