# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG ALPINE_IMAGE=docker.io/library/alpine:3.22.3@sha256:55ae5d250caebc548793f321534bc6a8ef1d116f334f18f4ada1b2daad3251b2

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
