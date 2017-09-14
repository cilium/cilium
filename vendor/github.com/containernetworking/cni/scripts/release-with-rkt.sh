#!/usr/bin/env bash
set -xe

SRC_DIR="${SRC_DIR:-$PWD}"

FEDORA_INSTALL="dnf install -y golang tar xz bzip2 gzip sudo iproute wget"
FEDORA_IMAGE="docker://fedora:23"
ACBUILD_URL="https://github.com/appc/acbuild/releases/download/v0.2.2/acbuild.tar.gz"
ACBUILD="acbuild --debug"
BUILDFLAGS="-a --ldflags '-extldflags \"-static\"'"

TAG=$(git describe --exact-match --abbrev=0) || TAG=$(git describe)
RELEASE_DIR=release-${TAG}
OUTPUT_DIR=bin

rm -Rf ${SRC_DIR}/${RELEASE_DIR}
mkdir -p ${SRC_DIR}/${RELEASE_DIR}

sudo -E rkt run \
    --volume rslvconf,kind=host,source=/etc/resolv.conf \
    --mount volume=rslvconf,target=/etc/resolv.conf \
    --volume src-dir,kind=host,source=$SRC_DIR \
    --mount volume=src-dir,target=/opt/src \
    --interactive \
    --insecure-options=image \
    ${FEDORA_IMAGE} \
    --exec /bin/bash \
    -- -xe -c "\
    ${FEDORA_INSTALL}; cd /opt/src; umask 0022; 
    for arch in amd64 arm arm64 ppc64le s390x; do \
        CGO_ENABLED=0 GOARCH=\$arch ./build ${BUILDFLAGS}; \
        for format in txz tbz2 tgz; do \
            FILENAME=cni-\$arch-${TAG}.\$format; \
            FILEPATH=${RELEASE_DIR}/\$FILENAME; \
            tar -C ${OUTPUT_DIR} --owner=0 --group=0 -caf \$FILEPATH .; \
            if [ \"\$arch\" == \"amd64\" ]; then \
                cp \$FILEPATH ${RELEASE_DIR}/cni-${TAG}.\$format; \
            fi; \
        done; \
    done; \
    wget -O - ${ACBUILD_URL} | tar -C /usr/bin -xzvf -; \
    ${ACBUILD} begin; \
    ${ACBUILD} set-name coreos.com/cni; \
    ${ACBUILD} label add version ${TAG}; \
    ${ACBUILD} copy --to-dir ${OUTPUT_DIR} /opt/cni/; \
    ${ACBUILD} write ${RELEASE_DIR}/cni-${TAG}.aci; \
    ${ACBUILD} end; \
    pushd ${RELEASE_DIR}; for f in \$(ls); do sha1sum \$f > \$f.sha1; done; popd; \
    chown -R ${UID} ${OUTPUT_DIR} ${RELEASE_DIR}; \
    :"
