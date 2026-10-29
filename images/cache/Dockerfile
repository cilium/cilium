# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG ALPINE_IMAGE=docker.io/library/alpine:3.22.7@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f

FROM ${ALPINE_IMAGE} AS import-cache

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
