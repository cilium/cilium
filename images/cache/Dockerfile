# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/alpine:3.19.4@sha256:7a85bf5dc56c949be827f84f9185161265c58f589bb8b2a6b6bb6d3076c1be21 AS import-cache

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
