# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/alpine:3.19.4@sha256:ae65dbf8749a7d4527648ccee1fa3deb6bfcae34cbc30fc67aa45c44dcaa90ee AS import-cache

RUN --mount=type=bind,target=/host-tmp \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    mkdir -p /root/.cache; \
    mkdir -p /go; \
    if [ -d /host-tmp/.cache/go-build ]; then \
      cp -r /host-tmp/.cache/go-build /root/.cache; \
    fi; \
    if [ -d /host-tmp/pkg ]; then \
      cp -r /host-tmp/pkg /go; \
    fi
