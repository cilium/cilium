#!/bin/bash

set -e
set -x

source /opt/cilium/env

envsubst '${VERSION} ${COMMIT} ${SHORTCOMMIT}' < \
	/opt/cilium/cilium.spec.envsubst > /opt/cilium/cilium.spec

echo $(git describe --tags $(git rev-list --tags --max-count=1) | tr -d '-').$(git rev-parse --short HEAD)
sed -i -re '/^Version/s/-//g' /opt/cilium/cilium.spec

# Install any lingering build requirements
dnf builddep -y /opt/cilium/cilium.spec

fedpkg --release f28 local

find /opt/cilium -type f -name 'cilium*.rpm' -exec mv -f "{}" /output/ \;
