# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c AS import-cache

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
