# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=scratch
ARG ALPINE_IMAGE=docker.io/library/alpine:3.18.4@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${ALPINE_IMAGE} as certs
RUN apk --update add ca-certificates

FROM ${BASE_IMAGE} as release
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
