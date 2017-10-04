#!/bin/bash

set -e
set -x

BUILD_DIR="/go/src/github.com/cilium/cilium"
BASE_DIR="/opt/cilium/"
SYSCONFIG_DIR="${BUILD_DIR}/contrib/systemd/"
BRANCH=$(cd ${BASE_DIR}/cilium; git rev-parse --abbrev-ref HEAD)
export VERSION=$(cat ${BASE_DIR}/cilium/VERSION)
echo $VERSION

mkdir -p ${BUILD_DIR}
mv ${BASE_DIR}/cilium/ $(dirname ${BUILD_DIR})
cp -R ${BASE_DIR}/debian ${BUILD_DIR}
cd ${BUILD_DIR}

python ${BASE_DIR}/changelog_parser.py NEWS.rst > debian/changelog
git archive --format tar ${BRANCH} | gzip > ../cilium_${VERSION}.orig.tar.gz
debuild -e GOPATH -e GOROOT -e PATH -us -uc
cp ../cilium_* /output/
