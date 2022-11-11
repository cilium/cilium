# syntax=docker/dockerfile:1.2

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/alpine:3.16.2@sha256:65a2763f593ae85fab3b5406dc9e80f744ec5b449f269b699b5efd37a07ad32e as import-cache

RUN --mount=type=bind,target=/host-tmp \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    mkdir -p /root/.cache/go-build; \
    mkdir -p /go/pkg; \
    if [ -f /host-tmp/go-build-cache.tar.gz ]; then \
      tar xzf /host-tmp/go-build-cache.tar.gz --no-same-owner -C /root/.cache/go-build; \
    fi; \
    if [ -f /host-tmp/go-pkg-cache.tar.gz ]; then \
      tar xzf /host-tmp/go-pkg-cache.tar.gz --no-same-owner -C /go/pkg; \
    fi

FROM docker.io/library/alpine:3.16.2@sha256:65a2763f593ae85fab3b5406dc9e80f744ec5b449f269b699b5efd37a07ad32e as cache-creator
RUN --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    tar czf /tmp/go-build-cache.tar.gz -C /root/.cache/go-build . ; \
    tar czf /tmp/go-pkg-cache.tar.gz -C /go/pkg .

FROM scratch as export-cache

COPY --from=cache-creator \
        /tmp/go-build-cache.tar.gz \
        /tmp/go-pkg-cache.tar.gz \
        /tmp/
